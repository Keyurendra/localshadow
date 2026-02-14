package container

import (
	"context"
	"fmt"
	"sort"
	"strings"

	namespaceapi "github.com/containerd/containerd/api/services/namespaces/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func nsList(ctx context.Context, host string) ([]string, error) {
	conn, err := grpc.NewClient(
		host,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("dial containerd namespace service: %w", err)
	}
	defer conn.Close()

	cli := namespaceapi.NewNamespacesClient(conn)
	resp, err := cli.List(ctx, &namespaceapi.ListNamespacesRequest{})
	if err != nil {
		return nil, fmt.Errorf("listing containerd namespaces: %w", err)
	}
	return nsExtract(resp.GetNamespaces()), nil
}

func nsExtract(items []*namespaceapi.Namespace) []string {
	var ns []string
	seen := make(map[string]struct{})
	for _, item := range items {
		if item == nil {
			continue
		}
		name := strings.TrimSpace(item.GetName())
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		ns = append(ns, name)
	}
	sort.Strings(ns)
	return ns
}
