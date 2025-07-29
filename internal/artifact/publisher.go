package artifact

import "context"

type Publisher interface {
	Publish(context.Context, ...Findings) error
}
