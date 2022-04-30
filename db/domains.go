package db

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/firestore"
	"github.com/google/uuid"
	"go.devnw.com/dns"
	"go.devnw.com/gois"
	"google.golang.org/api/iterator"
)

func (c *Client) GetDomain(
	ctx context.Context,
	userID string,
	domainID string) (*gois.Host, error) {
	domain, err := c.domainByID(ctx, userID, domainID)
	if err != nil {
		return nil, fmt.Errorf("failed to get domain: %s", err)
	}

	var h *gois.Host
	err = domain.DataTo(h)
	if err != nil {
		return nil, fmt.Errorf("failed to get domain: %s", err)
	}

	return h, nil
}

func (c *Client) GetDomains(ctx context.Context, userID string) ([]*gois.Host, error) {
	domains := []*gois.Host{}
	iter := c.domains(ctx, userID).Documents(ctx)
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("failed to get domains: %s", err)
		}

		h := &gois.Host{}
		err = doc.DataTo(h)
		if err != nil {
			// TODO: use publisher for client?
			// d.p.ErrorFunc(r.Context(), func() error {
			// 	return Err(r, err, "failed to unmarshal domain")
			// })

			continue
		}

		domains = append(domains, h)
	}

	return domains, nil
}

func (c *Client) CreateDomain(
	ctx context.Context,
	userID string,
	domain string,
) (*gois.Host, error) {
	// TODO: set this up so that if a domain exists but is not validated it
	// can be migrated to a new user and be validated.
	// This should happen after the current token is expired or invalidated.
	_, err := c.firestore.Collection("domains").Doc(domain).Get(ctx)
	if err == nil {
		return nil, fmt.Errorf("domain already exists")
	}

	// Generate domain challenge token
	token, err := dns.NewToken(domain, c.domainTokenKey, &c.domtainTokenExp)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %s", err)
	}

	host := &gois.Host{
		ID:      uuid.New().String(),
		Owner:   userID,
		Created: time.Now(),
		Domain:  domain,
		Token:   token,
	}

	_, err = c.firestore.Collection("domains").Doc(domain).Create(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("failed to create domain: %s", err)
	}

	return host, nil
}

func (c *Client) DeleteDomain(
	ctx context.Context,
	userID string,
	domainID string,
) error {
	domain, err := c.domainByID(ctx, userID, domainID)
	if err != nil {
		return fmt.Errorf("failed to get domain: %s", err)
	}

	_, err = domain.Ref.Delete(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete domain: %s", err)
	}

	return nil
}

func (c *Client) NewDomainToken(
	ctx context.Context,
	userID string,
	domainID string,
) (*dns.Token, error) {
	domainRef, err := c.domainByID(ctx, userID, domainID)
	if err != nil {
		return nil, fmt.Errorf("failed to get domain: %s", err)
	}

	var domain *gois.Host
	err = domainRef.DataTo(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get domain: %s", err)
	}

	// The domain is already validated so just return the existing token
	if domain.Token.Validated != nil {
		return domain.Token, nil
	}

	token, err := dns.NewToken(
		domain.Domain,
		c.domainTokenKey,
		&c.domtainTokenExp,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %s", err)
	}

	_, err = domainRef.Ref.Update(ctx, []firestore.Update{
		{
			Path:  "Token",
			Value: token,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update token: %s", err)
	}

	return token, nil
}

func (c *Client) UpdateDomainToken(
	ctx context.Context,
	userID string,
	domainID string,
	validated *time.Time,
) error {
	domain, err := c.domainByID(ctx, userID, domainID)
	if err != nil {
		return fmt.Errorf("failed to get domain: %s", err)
	}

	_, err = domain.Ref.Update(ctx, []firestore.Update{
		{
			Path:  "Token.Validated",
			Value: validated,
		},
		{
			Path:  "Token.Updated",
			Value: time.Now(),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to update token: %s", err)
	}

	return nil
}

func (c *Client) domainByID(
	ctx context.Context,
	userID,
	domainID string,
) (*firestore.DocumentSnapshot, error) {
	return c.firestore.Collection("domains").Where("Owner", "==", userID).
		Where("ID", "==", domainID).
		Limit(1).
		Documents(ctx).
		Next()
}

func (c *Client) domains(ctx context.Context, userID string) firestore.Query {
	return c.firestore.Collection("domains").Where("Owner", "==", userID)
}
