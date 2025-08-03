package gcp

import "strings"

const identifierPrefix = "accuknox-omni-993fa8af46"

func nameFromURI(uri string) string {
	parts := strings.Split(uri, "/")
	return parts[len(parts)-1]
}

func zoneFromURI(uri string) string {
	parts := strings.Split(uri, "/")
	for i := range parts {
		if parts[i] == "zones" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
