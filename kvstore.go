package gois

import "context"

type KVStore interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Put(ctx context.Context, key string, data []byte) error
	Delete(ctx context.Context, key string) error
}

func NewCache(local, remote KVStore) *Cache {
	return &Cache{
		local:  local,
		remote: remote,
	}
}

type Cache struct {
	local, remote KVStore
}

// Get returns a certificate data for the specified key.
// If there's no such key, Get returns ErrCacheMiss.
func (c *Cache) Get(ctx context.Context, key string) ([]byte, error) {
	// attempt lookup in local cache
	data, err := c.local.Get(ctx, key)
	if err == nil {
		return data, nil
	}

	data, err = c.remote.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	// Return the certificate data, and add it to the local cache.
	return data, c.local.Put(ctx, key, data)
}

// Put stores the data in the cache under the specified key.
// Underlying implementations may use any data storage format,
// as long as the reverse operation, Get, results in the original data.
func (c *Cache) Put(ctx context.Context, key string, data []byte) error {
	// Store local cache for quick lookup.
	defer func() {
		_ = c.local.Put(ctx, key, data)
	}()

	err := c.remote.Put(ctx, key, data)
	if err != nil {
		return err
	}

	return nil
}

// Delete removes the data from the local cache under the specified key.
// If there's no such key in the cache, Delete returns nil.
func (c *Cache) Delete(ctx context.Context, key string) error {
	// Delete local cache.
	_ = c.local.Delete(ctx, key)

	return nil
}
