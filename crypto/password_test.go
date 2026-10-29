package crypto

import (
	"errors"
	"testing"
)

func TestHashSlotsRefuseWhenFull(t *testing.T) {
	hash, err := HashPassword("password-12345")
	if err != nil {
		t.Fatal(err)
	}
	// take every slot, as parallel logins would.
	for i := 0; i < cap(hashSlots); i++ {
		if !acquireHashSlot() {
			t.Fatalf("slot %d not free", i)
		}
	}
	if _, err := VerifyPassword("password-12345", hash); !errors.Is(err, ErrBusy) {
		t.Fatalf("verify with no free slot: %v", err)
	}
	if _, err := HashPassword("x"); !errors.Is(err, ErrBusy) {
		t.Fatalf("hash with no free slot: %v", err)
	}
	for i := 0; i < cap(hashSlots); i++ {
		releaseHashSlot()
	}
	ok, err := VerifyPassword("password-12345", hash)
	if err != nil || !ok {
		t.Fatalf("verify after slots freed: %v %v", ok, err)
	}
	if n := cap(hashSlots); n < 2 || n > maxHashSlots {
		t.Fatalf("slot count %d", n)
	}
}
