package file

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	"github.com/accuknox/omniscan/pkg/publisher"
	"github.com/accuknox/omniscan/pkg/scanner"
)

type Publisher struct {
	storePath string
}

func NewPublisher(storePath string) publisher.Publisher {
	return Publisher{
		storePath: storePath,
	}
}

func (p Publisher) Publish(ctx context.Context, findings ...scanner.Findings) error {
	if err := os.MkdirAll(p.storePath, 0o755); err != nil {
		return fmt.Errorf("creating store directory %q: %w", p.storePath, err)
	}

	for _, f := range findings {
		path := filepath.Join(
			p.storePath,
			fmt.Sprintf("%s-%s.json", uuid.NewString(), f.DataType()),
		)
		err := os.WriteFile(path, f.JSON(), 0o644)
		if err != nil {
			return fmt.Errorf("writing to %q: %w", path, err)
		}
	}

	return nil
}
