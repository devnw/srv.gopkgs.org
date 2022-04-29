package db

import (
	"context"
	"time"

	"cloud.google.com/go/firestore"
)

func New(
	ctx context.Context,
	projectID string,
	domainTokenKey string,
	domtainTokenExp time.Duration,
) (*Client, error) {
	c, err := firestore.NewClient(ctx, projectID)
	if err != nil {
		return nil, err
	}

	return &Client{
		firestore:       c,
		domainTokenKey:  domainTokenKey,
		domtainTokenExp: domtainTokenExp,
	}, nil
}

type Client struct {
	firestore       *firestore.Client
	domainTokenKey  string
	domtainTokenExp time.Duration
}

func (c *Client) Close() error {
	return c.firestore.Close()
}
