package artifact

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
)

type Pubisher struct {
	c Config
}

func NewPublisher(c Config) (*Pubisher, error) {
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("validating provided config: %w", err)
	}
	return &Pubisher{c: c}, nil
}

func (p Pubisher) Publish(ctx context.Context, findings []Findings) error {
	for _, f := range findings {
		err := p.uploadFinding(ctx, f)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p Pubisher) buildArtifactURL(dataType string) (*url.URL, error) {
	u, err := url.Parse(p.c.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("parsing endpoint %q: %w", p.c.Endpoint, err)
	}

	q := u.Query()
	q.Set("tenant_id", strconv.FormatUint(uint64(p.c.TenantID), 10))
	q.Set("label_id", p.c.LabelID)
	q.Set("save_to_s3", "true")
	q.Set("data_type", dataType)
	u.RawQuery = q.Encode()

	return u, nil
}

func (p Pubisher) uploadFinding(ctx context.Context, f Findings) error {
	body, contentType, err := p.createMultipartBody(f)
	if err != nil {
		return fmt.Errorf("creating multipart form: %w", err)
	}

	url, err := p.buildArtifactURL(f.DataType())
	if err != nil {
		return fmt.Errorf("building artifact URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url.String(), body)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.c.Token)
	req.Header.Set("Content-Type", contentType)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}

	return nil
}

func (p Pubisher) createMultipartBody(f Findings) (io.Reader, string, error) {
	buf := new(bytes.Buffer)
	w := multipart.NewWriter(buf)

	part, err := w.CreateFormFile("file", "artifact.json")
	if err != nil {
		return nil, "", fmt.Errorf("creating form file: %w", err)
	}

	_, err = io.Copy(part, f.JSONReader())
	if err != nil {
		return nil, "", fmt.Errorf("copying %q findings: %w", f.DataType(), err)
	}

	err = w.Close()
	if err != nil {
		return nil, "", fmt.Errorf("closing multipart form: %w", err)
	}

	return buf, w.FormDataContentType(), nil
}
