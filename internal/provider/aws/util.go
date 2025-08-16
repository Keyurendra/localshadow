package aws

import "github.com/aws/aws-sdk-go-v2/service/ec2/types"

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
