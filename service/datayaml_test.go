package service

import (
	"reflect"
	"testing"
)

func TestPackageAttachments(t *testing.T) {
	files := map[string][]byte{
		"content/mail/data.yaml": []byte(`emails:
  - name: Invoice
    attachments:
      - name: invoice.pdf
        file: invoice.pdf
        inline: true
      - name: no file
`),
		"content/att/data.yaml": []byte(`attachments:
  - name: cal
    file: files/cal.ics
    calendar: true
`),
		"content/bad/data.yaml": []byte("emails: [unclosed"),
		"other/data.yaml":       []byte("attachments: [{name: x, file: x}]"),
	}
	got := PackageAttachments(files)
	want := []PackageAttachment{
		{Name: "cal", File: "content/att/files/cal.ics", Calendar: true},
		{Name: "invoice.pdf", File: "content/mail/invoice.pdf", Inline: true, EmailName: "Invoice"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if out := PackageAttachments(nil); out == nil || len(out) != 0 {
		t.Fatalf("empty input gave %#v, want an empty list", out)
	}
}
