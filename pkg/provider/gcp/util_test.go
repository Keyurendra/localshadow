package gcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const exampleURI = "https://www.googleapis.com/compute/v1/projects/accuknox-cnapp/zones/asia-south1-a/instances/test-a"

func TestNameFromURI(t *testing.T) {
	name := nameFromURI(exampleURI)
	assert.Equal(t, "test-a", name)
}

func TestZoneFromURI(t *testing.T) {
	zone := zoneFromURI(exampleURI)
	assert.Equal(t, "asia-south1-a", zone)
}

func TestRegionFromZone(t *testing.T) {
	region := regionFromZone("asia-south1-a")
	assert.Equal(t, "asia-south1", region)
}
