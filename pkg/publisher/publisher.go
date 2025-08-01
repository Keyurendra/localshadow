package publisher

import (
	"context"

	"github.com/accuknox/omniscan/pkg/scanner"
)

type Publisher interface {
	Publish(context.Context, ...scanner.Findings) error
}
