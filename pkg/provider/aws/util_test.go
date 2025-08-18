package aws

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	region      = "us-east-1"
	accountID   = "999999999999"
	instanceID  = "i-0ded265c9d72b9c3a"
	instanceARN = "arn:aws:ec2:" + region + ":" + accountID + ":instance/" + instanceID
)

func TestBuildInstanceARN(t *testing.T) {
	p := Provider{region: region, accountID: accountID}
	got := p.buildInstanceARN(instanceID)
	if assert.Equal(t, instanceARN, got) {
		t.Log(got)
	}
}

func TestExtractInstanceID(t *testing.T) {
	p := Provider{region: region, accountID: accountID}
	got := p.extractInstanceID(instanceARN)
	if assert.Equal(t, instanceID, got) {
		t.Log(got)
	}
}
