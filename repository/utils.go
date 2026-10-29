// Package repository holds GORM data access. The column allowlist helpers here
// are the injection prevention layer, copied in pattern from phishingclub: a
// user supplied order column is never interpolated, it must pass an explicit
// allowlist first. Search columns are fixed by the repository, never user
// supplied; only the search value goes through a gorm placeholder.
package repository

import (
	"errors"
	"fmt"
	"slices"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// QueryArgs are the pagination, ordering and search parameters from a request.
// OrderBy is validated against an allowlist before it reaches SQL. Search is the
// user's query string, bound as a value and only ever matched against the
// repository's own fixed search columns.
type QueryArgs struct {
	Offset  int
	Limit   int
	OrderBy string
	Desc    bool
	Search  string
	// FilterType, FilterNamespace and FilterTag are exact match package list
	// filters (empty means no filter). They are bound as values, never as column
	// names, so they carry no injection surface; only ListPackages reads them.
	FilterType      string
	FilterNamespace string
	FilterTag       string
}

// ErrOrderColumn is returned when a list asks to sort by a column outside the
// table's order allowlist.
var ErrOrderColumn = errors.New("order column not allowed")

// applyOrder adds an ORDER BY only when q.OrderBy names a column in orderCols,
// the per table allowlist of orderable columns. A column outside the allowlist
// returns an error, so an unknown or crafted column never reaches SQL. The
// column goes to GORM as an identifier, which GORM quotes.
func applyOrder(db *gorm.DB, q *QueryArgs, orderCols []clause.Column) (*gorm.DB, error) {
	if q == nil || q.OrderBy == "" {
		return db, nil
	}
	i := slices.IndexFunc(orderCols, func(c clause.Column) bool { return c.Name == q.OrderBy })
	if i < 0 {
		return db, fmt.Errorf("%w: %s", ErrOrderColumn, q.OrderBy)
	}
	// NOCASE gives case insensitive text ordering; integer columns are still
	// compared numerically, and datetimes are stored RFC3339 so they still sort
	// chronologically. Only text columns whose semver meaning NOCASE would break
	// (version) are kept out of every order allowlist.
	order := "? COLLATE NOCASE ASC"
	if q.Desc {
		order = "? COLLATE NOCASE DESC"
	}
	return db.Order(clause.OrderBy{
		Expression: clause.Expr{SQL: order, Vars: []any{orderCols[i]}},
	}), nil
}

// applySearch adds a case insensitive LIKE filter across searchCols, the
// repository's own fixed columns (never user supplied). The user value is bound
// as a parameter with its LIKE wildcards escaped, so it matches only as typed.
func applySearch(db *gorm.DB, q *QueryArgs, searchCols []clause.Column) *gorm.DB {
	if q == nil || q.Search == "" || len(searchCols) == 0 {
		return db
	}
	pattern := "%" + escapeLike(q.Search) + "%"
	likes := make([]clause.Expression, 0, len(searchCols))
	for _, c := range searchCols {
		likes = append(likes, clause.Expr{SQL: `? LIKE ? COLLATE NOCASE ESCAPE '\'`, Vars: []any{c, pattern}})
	}
	return db.Where(clause.Or(likes...))
}

// applyPage adds OFFSET/LIMIT. A zero limit means no paging (used for the full
// row reads the service does internally).
func applyPage(db *gorm.DB, q *QueryArgs) *gorm.DB {
	if q == nil || q.Limit == 0 {
		return db
	}
	return db.Offset(q.Offset).Limit(q.Limit)
}
