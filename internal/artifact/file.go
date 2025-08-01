package artifact

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/accuknox/omniscan/pkg/scanner"
)

const isosecLayout = "20060102150405"

type FilePublisher struct {
	storePath string
}

func NewFilePublisher(storePath string) Publisher {
	return FilePublisher{
		storePath: storePath,
	}
}

func (p FilePublisher) Publish(ctx context.Context, findings ...scanner.Findings) error {
	if err := os.MkdirAll(p.storePath, 0o755); err != nil {
		return fmt.Errorf("creating store directory %q: %w", p.storePath, err)
	}

	for _, f := range findings {
		path := filepath.Join(
			p.storePath,
			fmt.Sprintf(
				"%s-%s.json",
				time.Now().Format(isosecLayout), f.DataType(),
			),
		)
		err := os.WriteFile(path, f.JSON(), 0o644)
		if err != nil {
			return fmt.Errorf("writing to %q: %w", path, err)
		}
	}

	return nil
}
