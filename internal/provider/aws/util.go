package aws

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

const identifierPrefix = "accuknox-omni-993fa8af46"

func resourceNameFromTags(tags []types.Tag) string {
	for _, t := range tags {
		if t.Key == nil || t.Value == nil {
			continue
		}
		if *t.Key == "Name" {
			return *t.Value
		}
	}
	return ""
}

func (p *Provider) buildInstanceARN(instanceID string) string {
	return fmt.Sprintf(
		"arn:aws:ec2:%s:%s:instance/%s",
		p.region, p.accountID, instanceID,
	)
}

func (p *Provider) extractInstanceID(arn string) string {
	parts := strings.Split(arn, "/")
	if len(parts) != 2 || !strings.Contains(arn, ":instance/") {
		return ""
	}
	return parts[1]
}
