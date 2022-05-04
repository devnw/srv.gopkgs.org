package gois

import (
	"context"
	"time"

	"go.devnw.com/dns"
)

type DB interface {
	GetDomains(ctx context.Context, userID string) ([]*Host, error)

	GetDomainByName(
		ctx context.Context,
		domain string,
	) (*Host, error)

	GetDomainForUser(
		ctx context.Context,
		userID string,
		domainID string,
	) (*Host, error)

	CreateDomain(
		ctx context.Context,
		userID string,
		domain string,
	) (*Host, error)

	DeleteDomain(
		ctx context.Context,
		userID string,
		domainID string,
	) error

	UpdateModules(
		ctx context.Context,
		userID string,
		domainID string,
		modules ...*Module,
	) error

	DeleteModule(
		ctx context.Context,
		userID string,
		domainID string,
		path string,
	) error

	NewDomainToken(
		ctx context.Context,
		userID string,
		domainID string,
	) (*dns.Token, error)

	UpdateDomainToken(
		ctx context.Context,
		userID string,
		domainID string,
		validated *time.Time,
	) error
}
