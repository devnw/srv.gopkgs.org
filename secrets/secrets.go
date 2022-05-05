package secrets

import (
	"context"
	"fmt"

	secrets "cloud.google.com/go/secretmanager/apiv1"
	secretspb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

func NewManager(ctx context.Context, project string) (*Manager, error) {
	client, err := secrets.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to setup client: %v", err)
	}

	return &Manager{
		client:  client,
		project: project,
	}, nil
}

type Manager struct {
	client  *secrets.Client
	project string
}

func (m Manager) Get(ctx context.Context, key string) ([]byte, error) {
	result, err := m.get(ctx, key)
	if err != nil {
		return nil, err
	}

	return result.Payload.Data, nil
}

func (m Manager) Put(ctx context.Context, key string, data []byte) error {
	var name string

	// Only add to secrets manager if the key doesn't already exist
	result, err := m.get(ctx, key)
	if err == nil {
		name = result.Name
	} else {
		// push to secret manager
		// Create the request to create the secret.
		createSecretReq := &secretspb.CreateSecretRequest{
			Parent:   fmt.Sprintf("projects/%s", m.project),
			SecretId: key, // pragma: allowlist secret
			Secret: &secretspb.Secret{
				Replication: &secretspb.Replication{
					Replication: &secretspb.Replication_Automatic_{
						Automatic: &secretspb.Replication_Automatic{},
					},
				},
			},
		}

		var secret *secretspb.Secret
		secret, err = m.client.CreateSecret(ctx, createSecretReq)
		if err != nil {
			return fmt.Errorf("failed to create secret: %v", err)
		}

		name = secret.Name
	}

	// Update the version of the secret
	addSecretVersionReq := &secretspb.AddSecretVersionRequest{
		Parent: name,
		Payload: &secretspb.SecretPayload{
			Data: data,
		},
	}

	// Call the API.
	_, err = m.client.AddSecretVersion(ctx, addSecretVersionReq)
	if err != nil {
		return fmt.Errorf("failed to add secret version: %v", err)
	}

	return nil
}

func (m Manager) Delete(ctx context.Context, key string) error {
	return nil
}

func (m Manager) get(
	ctx context.Context,
	key string,
) (*secretspb.AccessSecretVersionResponse, error) {
	// Lookup the latest secret for this key in secrets manager.
	accessRequest := &secretspb.AccessSecretVersionRequest{
		Name: fmt.Sprintf(
			"projects/%s/secrets/%s/versions/latest",
			m.project,
			key,
		),
	}

	// Call the Secret Manager API to get the secret.
	result, err := m.client.AccessSecretVersion(ctx, accessRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %v", err)
	}

	return result, nil
}

func (m Manager) Close() error {
	err := m.client.Close()
	if err != nil {
		return fmt.Errorf("failed to close client: %v", err)
	}

	return nil
}
