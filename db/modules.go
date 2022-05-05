package db

import (
	"context"
	"fmt"

	"cloud.google.com/go/firestore"
	"go.devnw.com/gois"
)

func (c *Client) UpdateModules(
	ctx context.Context,
	userID string,
	domainID string,
	modules ...*gois.Module,
) error {
	if len(modules) == 0 {
		return fmt.Errorf("no modules provided")
	}

	if userID == "" {
		return fmt.Errorf("userID is required")
	}

	if domainID == "" {
		return fmt.Errorf("domainID is required")
	}

	domain, err := c.domainByID(ctx, userID, domainID)
	if err != nil {
		return fmt.Errorf(
			"failed to get domain by ID [%s] for user [%s]: %s",
			domainID,
			userID,
			err,
		)
	}

	h := &gois.Host{}
	err = domain.DataTo(h)
	if err != nil {
		return fmt.Errorf("failed to unmarshal domain: %s", err)
	}

	if h.Token.Validated == nil ||
		!h.Token.Validated.Before(h.Token.ValidateBy) {
		return fmt.Errorf("token not validated")
	}

	updates := []firestore.Update{}
	for _, mod := range modules {
		updates = append(
			updates,
			firestore.Update{
				Path:  fmt.Sprintf("Modules.%s", mod.Path),
				Value: mod,
			},
		)
	}

	_, err = domain.Ref.Update(ctx, updates)
	if err != nil {
		return fmt.Errorf("failed to update modules: %s", err)
	}

	return nil
}

func (c *Client) DeleteModule(
	ctx context.Context,
	userID string,
	domainID string,
	path string,
) error {
	if userID == "" {
		return fmt.Errorf("userID is required")
	}

	if domainID == "" {
		return fmt.Errorf("domainID is required")
	}

	if path == "" {
		return fmt.Errorf("path is required")
	}

	domain, err := c.domainByID(ctx, userID, domainID)
	if err != nil {
		return fmt.Errorf("failed to get domain: %s", err)
	}

	_, err = domain.Ref.Update(ctx, []firestore.Update{
		{Path: fmt.Sprintf("Modules.%s", path), Value: firestore.Delete},
	})
	if err != nil {
		return fmt.Errorf("failed to delete module: %s", err)
	}

	return nil
}
