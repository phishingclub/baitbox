package service

import (
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// PackageAttachment is one email attachment declared in a package data.yaml,
// shown on the package page so an email's attachments read as attachments, not
// loose files. File is the path within the archive, so the view can match it to
// the file's thumbnail and size. EmailName is empty for an attachment package.
type PackageAttachment struct {
	Name        string `json:"name"`
	File        string `json:"file"`
	Description string `json:"description,omitempty"`
	Embedded    bool   `json:"embedded"`
	Inline      bool   `json:"inline"`
	Calendar    bool   `json:"calendar"`
	EmailName   string `json:"emailName,omitempty"`
}

// dataYAML is the part of a content folder's data.yaml that lists attachments:
// nested under each email, or at the top level of an attachment package.
type dataYAML struct {
	Emails      []dataYAMLEmail      `yaml:"emails"`
	Attachments []dataYAMLAttachment `yaml:"attachments"`
}

type dataYAMLEmail struct {
	Name        string               `yaml:"name"`
	Attachments []dataYAMLAttachment `yaml:"attachments"`
}

type dataYAMLAttachment struct {
	Name        string `yaml:"name"`
	File        string `yaml:"file"`
	Description string `yaml:"description"`
	Embedded    bool   `yaml:"embedded"`
	Inline      bool   `yaml:"inline"`
	Calendar    bool   `yaml:"calendar"`
}

// PackageAttachments reads every content folder's data.yaml in files and returns
// its attachments with each file path resolved relative to its folder. A folder
// whose data.yaml does not parse is skipped so the rest still show. The result
// is sorted by data.yaml path so the order is stable across requests.
func PackageAttachments(files map[string][]byte) []PackageAttachment {
	paths := make([]string, 0, len(files))
	for p := range files {
		if strings.HasPrefix(p, "content/") && strings.HasSuffix(p, "/data.yaml") {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	out := []PackageAttachment{}
	for _, p := range paths {
		prefix := strings.TrimSuffix(p, "data.yaml")
		var dy dataYAML
		if err := yaml.Unmarshal(files[p], &dy); err != nil {
			continue
		}
		add := func(a dataYAMLAttachment, emailName string) {
			if a.File == "" {
				return
			}
			out = append(out, PackageAttachment{
				Name: a.Name, File: prefix + a.File, Description: a.Description,
				Embedded: a.Embedded, Inline: a.Inline, Calendar: a.Calendar,
				EmailName: emailName,
			})
		}
		for _, e := range dy.Emails {
			for _, a := range e.Attachments {
				add(a, e.Name)
			}
		}
		for _, a := range dy.Attachments {
			add(a, "")
		}
	}
	return out
}
