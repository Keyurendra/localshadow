package file

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	"github.com/Keyurendra/shadowtest/pkg/publisher"
	"github.com/Keyurendra/shadowtest/pkg/scanner"
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
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %w", path, err)
		}
		if err := json.MarshalWrite(file, f); err != nil {
			file.Close()
			return fmt.Errorf("writing to %q: %w", path, err)
		}
		file.Close()
	}

	return nil
}
