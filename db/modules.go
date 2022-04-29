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
	domain, err := c.domainByID(ctx, userID, domainID)
	if err != nil {
		return fmt.Errorf("failed to get domain: %s", err)
	}

	var h *gois.Host
	err = domain.DataTo(h)
	if err != nil {
		return fmt.Errorf("failed to get domain: %s", err)
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
