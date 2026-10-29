package service

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/phishingclub/baitbox/config"
	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/repository"
	"gorm.io/gorm"
)

const testOrigin = "https://localhost:8113"

// softKey is a software passkey: one P-256 key that signs assertions.
type softKey struct {
	priv    *ecdsa.PrivateKey
	id      []byte
	counter uint32
}

func newSoftKey(t *testing.T) *softKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &softKey{priv: priv, id: id}
}

// coseKey returns the public key in the COSE form a registration stores.
func (k *softKey) coseKey(t *testing.T) []byte {
	t.Helper()
	pub := k.priv.PublicKey
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	b, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.EllipticKey), Algorithm: int64(webauthncose.AlgES256)},
		Curve:         int64(webauthncose.P256),
		XCoord:        x,
		YCoord:        y,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// assert builds the browser JSON for an assertion over the challenge, with the
// backup eligible and backup state flags set as asked.
func (k *softKey) assert(t *testing.T, challenge, userHandle string, be, bs bool) []byte {
	t.Helper()
	k.counter++
	rpHash := sha256.Sum256([]byte("localhost"))
	flags := byte(0x01) // user present
	if be {
		flags |= 0x08
	}
	if bs {
		flags |= 0x10
	}
	auth := append([]byte{}, rpHash[:]...)
	auth = append(auth, flags)
	var ctr [4]byte
	binary.BigEndian.PutUint32(ctr[:], k.counter)
	auth = append(auth, ctr[:]...)
	clientData, _ := json.Marshal(map[string]string{"type": "webauthn.get", "challenge": challenge, "origin": testOrigin})
	cdHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, auth...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	body, _ := json.Marshal(map[string]any{
		"id":    enc(k.id),
		"rawId": enc(k.id),
		"type":  "public-key",
		"response": map[string]string{
			"clientDataJSON":    enc(clientData),
			"authenticatorData": enc(auth),
			"signature":         enc(sig),
			"userHandle":        enc([]byte(userHandle)),
		},
	})
	return body
}

// passkeyFixture is an operator with one software passkey stored as row.
type passkeyFixture struct {
	gdb *gorm.DB
	svc *WebAuthnService
	db  *repository.WebAuthnRepository
	op  *database.Operator
	key *softKey
	row *database.OperatorCredential
}

func newPasskeyFixture(t *testing.T, storedBE bool) *passkeyFixture {
	t.Helper()
	db := newTestDB(t)
	op := &database.Operator{Username: "alice", PasswordHash: "x"}
	if err := db.Create(op).Error; err != nil {
		t.Fatal(err)
	}
	key := newSoftKey(t)
	row := &database.OperatorCredential{
		OperatorID:      op.ID,
		Name:            "Passkey",
		CredentialID:    key.id,
		PublicKey:       key.coseKey(t),
		AttestationType: "none",
		BackupEligible:  storedBE,
		BackupState:     storedBE,
	}
	repo := repository.NewWebAuthnRepository(db)
	if err := repo.CreateDropSessions(row, ""); err != nil {
		t.Fatal(err)
	}
	// adding the passkey raised the auth epoch, so read the row a login would see.
	if err := db.Where("id = ?", op.ID).First(op).Error; err != nil {
		t.Fatal(err)
	}
	svc, err := NewWebAuthnService(repo, &config.Config{Env: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	return &passkeyFixture{gdb: db, svc: svc, db: repo, op: op, key: key, row: row}
}

// login runs one passkey login ceremony with the given flags.
func (f *passkeyFixture) login(t *testing.T, be, bs bool) error {
	t.Helper()
	opts, token, err := f.svc.BeginLogin(f.op, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	body := f.key.assert(t, opts.Response.Challenge.String(), f.op.ID, be, bs)
	req := httptest.NewRequest("POST", "/admin/passkeys/login/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	got, _, err := f.svc.FinishLogin(testOrigin, token, req, nil)
	if err == nil && (got == nil || got.ID != f.op.ID) {
		t.Fatalf("login returned the wrong operator")
	}
	return err
}

func (f *passkeyFixture) stored(t *testing.T) database.OperatorCredential {
	t.Helper()
	rows, err := f.db.ListByOperator(f.op.ID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("list passkeys: %v %d", err, len(rows))
	}
	return rows[0]
}

func TestPasskeyLoginSyncedPasskeyWithStoredFlags(t *testing.T) {
	f := newPasskeyFixture(t, true)
	if err := f.login(t, true, true); err != nil {
		t.Fatalf("synced passkey login failed: %v", err)
	}
	// the eligible flag of a credential never changes, so a flip is refused
	if err := f.login(t, false, false); err == nil {
		t.Fatal("login with a changed backup eligible flag must fail")
	}
}

func TestPasskeyLoginDeviceBoundPasskey(t *testing.T) {
	f := newPasskeyFixture(t, false)
	if err := f.login(t, false, false); err != nil {
		t.Fatalf("device bound passkey login failed: %v", err)
	}
}

// TestPasskeyLoginBackupStateUpdates: a passkey may be synced after it was
// made, so the backup state is updated at login.
func TestPasskeyLoginBackupStateUpdates(t *testing.T) {
	f := newPasskeyFixture(t, true)
	if err := f.login(t, true, false); err != nil {
		t.Fatalf("first login failed: %v", err)
	}
	if f.stored(t).BackupState {
		t.Fatal("backup state not cleared")
	}
	if err := f.login(t, true, true); err != nil {
		t.Fatalf("second login failed: %v", err)
	}
	if !f.stored(t).BackupState {
		t.Fatal("backup state not updated")
	}
}
