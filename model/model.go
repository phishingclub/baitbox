// Package model holds the domain validation for the registry entities. The
// database package carries the schema structs and the repository package the
// data access; the rules a value must satisfy before it is persisted live here,
// so a controller and a service enforce the same limits from one place. This
// mirrors the phishingclub layering (controller, service, repository, model,
// database).
package model

import "regexp"

// nsNameRe matches a usable namespace name: a lowercase slug. It mirrors the
// namespace part of a package id (manifest.idRe) so a namespace name can always
// be the namespace part of an address a package publishes to.
var nsNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// pkgNameRe matches a usable package name: the name part of a package id
// (manifest.idRe), so a rename cannot produce an address that could never
// publish.
var pkgNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// ValidNamespaceName reports whether name is a usable namespace slug.
func ValidNamespaceName(name string) bool { return nsNameRe.MatchString(name) }

// ValidPackageName reports whether name is a usable package name slug.
func ValidPackageName(name string) bool { return pkgNameRe.MatchString(name) }
