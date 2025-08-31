package metric

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Collector struct {
	port                uint16
	logger              *slog.Logger
	registry            *prometheus.Registry
	errorCount          *prometheus.CounterVec
	successfulScanCount *prometheus.CounterVec
}

func NewCollector(port uint16) (*Collector, error) {
	registry := prometheus.NewRegistry()
	errorCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "omni_error_count",
			Help: "Total number of errors by type and OS",
		},
		[]string{"type", "os"},
	)
	successfulScanCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "omni_successful_scan_count",
			Help: "Total number of successful scans by type and OS",
		},
		[]string{"type", "os"},
	)

	if err := registry.Register(errorCount); err != nil {
		return nil, fmt.Errorf("registering error_count metric: %w", err)
	}

	if err := registry.Register(successfulScanCount); err != nil {
		return nil, fmt.Errorf("registering successful_scan_count metric: %w", err)
	}

	return &Collector{
		port:                port,
		registry:            registry,
		errorCount:          errorCount,
		successfulScanCount: successfulScanCount,
	}, nil
}

func (c *Collector) RecordError(errTyp ErrorType, os OSType) {
	c.errorCount.WithLabelValues(errTyp.String(), os.String()).Inc()
}

func (c *Collector) RecordSuccessfulScan(scanTyp ScanType, os OSType) {
	c.successfulScanCount.WithLabelValues(scanTyp.String(), os.String()).Inc()
}

func (c Collector) ServeHTTP(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(c.registry, promhttp.HandlerOpts{}))
	srv := http.Server{
		Addr:    fmt.Sprintf(":%d", c.port),
		Handler: mux,
	}

	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()

		<-ctx.Done()

		// graceful termination
		ctx, cancel := context.WithTimeout(ctx, time.Second*30)
		defer cancel()

		err := srv.Shutdown(ctx)
		if err != nil {
			slog.LogAttrs(
				ctx,
				slog.LevelError,
				"forcefully shutting down",
				slog.Any("error", err),
			)
		}
	}()

	if err := srv.ListenAndServe(); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}

	return nil
}
