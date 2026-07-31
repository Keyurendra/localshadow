package macos

import (
	"net/http"
	"time"
)

const defaultFeedURL = "https://sofafeed.macadmins.io/v1/macos_data_feed.json"

type OptFunc func(*opts)

type opts struct {
	feedURL string
	client  *http.Client
}

func WithFeedURL(url string) OptFunc {
	return func(o *opts) {
		o.feedURL = url
	}
}

func WithHTTPClient(client *http.Client) OptFunc {
	return func(o *opts) {
		if client == nil {
			return
		}
		o.client = client
	}
}

func defaultOpts() opts {
	return opts{
		feedURL: defaultFeedURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}
