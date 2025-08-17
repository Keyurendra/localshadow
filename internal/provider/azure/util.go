package azure

import "strings"

const identifierPrefix = "accuknox-omni-993fa8af46"

func nameFromURI(uri string) string {
	parts := strings.Split(uri, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

func resourceGroupFromURI(uri string) string {
	parts := strings.Split(uri, "/")
	for i, part := range parts {
		if strings.EqualFold(part, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
