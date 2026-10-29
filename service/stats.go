package service

import (
	"github.com/phishingclub/baitbox/repository"
)

// Counts holds registry totals shown on the admin dashboard.
type Counts struct {
	Namespaces int64
	Packages   int64
	Versions   int64
	Downloads  int64
	Tokens     int64
}

// StatsService reports registry totals.
type StatsService struct {
	repo *repository.StatsRepository
}

// NewStatsService returns a StatsService.
func NewStatsService(repo *repository.StatsRepository) *StatsService {
	return &StatsService{repo: repo}
}

// Counts returns the current registry totals.
func (s *StatsService) Counts() (Counts, error) {
	var c Counts
	var err error
	if c.Namespaces, err = s.repo.CountNamespaces(); err != nil {
		return c, err
	}
	if c.Packages, err = s.repo.CountPackages(); err != nil {
		return c, err
	}
	if c.Versions, err = s.repo.CountVersions(); err != nil {
		return c, err
	}
	if c.Downloads, err = s.repo.SumDownloads(); err != nil {
		return c, err
	}
	if c.Tokens, err = s.repo.CountActiveTokens(); err != nil {
		return c, err
	}
	return c, nil
}
