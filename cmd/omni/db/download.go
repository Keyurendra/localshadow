package db

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/javadb"
	"github.com/aquasecurity/trivy/pkg/oci"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/urfave/cli/v3"
)

const (
	vulnDBMediaType = "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip"
	javaDBMediaType = "application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip"
)

var downloadCmd = &cli.Command{
	Name: "download",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:      "destination",
			TakesFile: true,
			Value:     "/var/lib/accuknox-omni/",
			Config:    cli.StringConfig{TrimSpace: true},
		},
		&cli.StringFlag{
			Name:   "vuln-db-repository",
			Value:  "ghcr.io/aquasecurity/trivy-db",
			Config: cli.StringConfig{TrimSpace: true},
		},
		&cli.StringFlag{
			Name:   "java-db-repository",
			Value:  "ghcr.io/aquasecurity/trivy-java-db",
			Config: cli.StringConfig{TrimSpace: true},
		},
		&cli.StringFlag{
			Name:   "msrc-db-url",
			Value:  "https://accuknox-windows-vuln-db.s3.us-east-1.amazonaws.com/db.sqlite3",
			Config: cli.StringConfig{TrimSpace: true},
		},
		&cli.BoolFlag{
			Name:  "quiet",
			Value: false,
		},
		&cli.BoolFlag{
			Name:  "force",
			Value: false,
		},
	},
	Arguments: []cli.Argument{
		&cli.StringArgs{
			Name:      "databases",
			Max:       2,
			Min:       1,
			Config:    cli.StringConfig{TrimSpace: true},
			UsageText: "[vuln java msrc]",
		},
	},
	Action: func(ctx context.Context, c *cli.Command) error {
		databases := slices.Compact(c.StringArgs("databases"))
		if len(databases) == 0 {
			return fmt.Errorf("no database specified")
		}

		vulnDBRepo := c.String("vuln-db-repository")
		javaDBRepo := c.String("java-db-repository")
		msrcDBUrl := c.String("msrc-db-url")
		cacheDir := c.String("destination")
		quiet := c.Bool("quiet")
		force := c.Bool("force")

		for _, database := range databases {
			switch database {
			case "vuln":
				needsUpdate, err := needsUpdate(cacheDir, database)
				if err != nil {
					return fmt.Errorf("determining if an update is needed: %w", err)
				}
				if !needsUpdate && !force {
					slog.LogAttrs(
						ctx,
						slog.LevelInfo,
						"vuln db is fairly recent. Skipping...",
					)
					continue
				}
				destination := filepath.Join(cacheDir, "db")
				repo, err := parseRepository(vulnDBRepo, db.SchemaVersion)
				if err != nil {
					return fmt.Errorf("parsing repository %s: %w", vulnDBRepo, err)
				}
				artifacts := oci.NewArtifacts([]name.Reference{repo}, types.RegistryOptions{})
				err = artifacts.Download(ctx, destination, oci.DownloadOption{
					MediaType: vulnDBMediaType,
					Quiet:     quiet,
				})
				if err != nil {
					return fmt.Errorf("downloading vuln database: %w", err)
				}
			case "java":
				needsUpdate, err := needsUpdate(cacheDir, database)
				if err != nil {
					return fmt.Errorf("determining if an update is needed: %w", err)
				}
				if !needsUpdate && !force {
					slog.LogAttrs(
						ctx,
						slog.LevelInfo,
						"java db is fairly recent. Skipping...",
					)
					continue
				}
				destination := filepath.Join(cacheDir, "java-db")
				repo, err := parseRepository(javaDBRepo, javadb.SchemaVersion)
				if err != nil {
					return fmt.Errorf("parsing repository %s: %w", javaDBRepo, err)
				}
				artifacts := oci.NewArtifacts([]name.Reference{repo}, types.RegistryOptions{})
				err = artifacts.Download(ctx, destination, oci.DownloadOption{
					MediaType: javaDBMediaType,
					Quiet:     quiet,
				})
				if err != nil {
					return fmt.Errorf("downloading java database: %w", err)
				}
			case "msrc":
				destination := filepath.Join(cacheDir, "msrc", "msrc.sqlite")
				if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
					return fmt.Errorf("creating directory %s: %w", filepath.Dir(destination), err)
				}

				out, err := os.Create(destination)
				if err != nil {
					return fmt.Errorf("creating file %s: %w", destination, err)
				}
				defer out.Close()

				resp, err := http.Get(msrcDBUrl)
				if err != nil {
					return fmt.Errorf("failed to download: %w", err)
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					return fmt.Errorf("bad status: %s", resp.Status)
				}

				if _, err := io.Copy(out, resp.Body); err != nil {
					return fmt.Errorf("failed to write file: %w", err)
				}
			default:
				slog.LogAttrs(
					ctx,
					slog.LevelError,
					"Unknown database passed...Ignoring",
					slog.String("argument", database),
				)
			}
		}
		return nil
	},
}

func parseRepository(repo string, schemaVersion int) (name.Reference, error) {
	dbRepository, err := name.ParseReference(repo, name.WithDefaultTag(""))
	if err != nil {
		return nil, err
	}

	t, ok := dbRepository.(name.Tag)
	if !ok || t.TagStr() != "" {
		return dbRepository, nil
	}

	dbRepository = t.Tag(strconv.Itoa(schemaVersion))
	return dbRepository, nil
}

func needsUpdate(dir string, typ string) (bool, error) {
	if !fsutils.DirExists(dir) {
		return true, nil
	}
	dbFile := filepath.Join("db", "trivy.db")
	threshold := time.Hour * 24
	if typ == "java" {
		dbFile = filepath.Join("java-db", "trivy-java.db")
		threshold = time.Hour * 24 * 3
	}
	dbFile = filepath.Join(dir, dbFile)
	info, err := os.Stat(dbFile)
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, fmt.Errorf("getting db file info: %w", err)
	}
	return time.Since(info.ModTime()) > threshold, nil
}
