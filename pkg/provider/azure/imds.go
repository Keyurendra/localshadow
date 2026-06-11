package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const imdsURL = "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01&format=json"

type identity struct {
	Location          string `json:"location"`
	ResourceGroupName string `json:"resourceGroupName"`
	SubscriptionID    string `json:"subscriptionId"`
	Name              string `json:"name"`
	Zone              string `json:"zone"`
}

func queryIMDS(ctx context.Context) (*identity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, imdsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating imds request: %w", err)
	}
	req.Header.Add("Metadata", "true")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IMDS returned status %d", resp.StatusCode)
	}

	identity := new(identity)
	if err := json.NewDecoder(resp.Body).Decode(identity); err != nil {
		return nil, fmt.Errorf("decoding imds response: %w", err)
	}

	return identity, nil
}
