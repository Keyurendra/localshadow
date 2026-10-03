package publisher

import (
	"context"

	"github.com/Keyurendra/shadowtest/pkg/scanner"
)

type Publisher interface {
	Publish(context.Context, ...scanner.Findings) error
}
