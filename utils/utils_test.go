package utils

import (
	"reflect"
	"testing"
)

func TestNonNil(t *testing.T) {
	if got := NonNil[string](nil); got == nil || len(got) != 0 {
		t.Fatalf("nil gave %#v", got)
	}
	in := []int{1}
	if got := NonNil(in); !reflect.DeepEqual(got, in) {
		t.Fatalf("got %v", got)
	}
}

func TestSplitTrim(t *testing.T) {
	if got := SplitTrim(" a, ,b ,", ","); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("got %#v", got)
	}
	if got := SplitTrim("", ","); got == nil || len(got) != 0 {
		t.Fatalf("empty gave %#v", got)
	}
}

func TestTruncateRunes(t *testing.T) {
	if got := TruncateRunes("håndværk", 4); got != "hånd" {
		t.Fatalf("got %q", got)
	}
	if got := TruncateRunes("ab", 4); got != "ab" {
		t.Fatalf("got %q", got)
	}
}

func TestFormatMiB(t *testing.T) {
	if got := FormatMiB(3 << 19); got != "1.5 MiB" {
		t.Fatalf("got %q", got)
	}
}
