package api

import (
	"context"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	middleware "github.com/deepmap/oapi-codegen/pkg/gin-middleware"
	"github.com/gin-gonic/gin"
	"github.com/nitinjangam/go-utils/correlation"
	"github.com/nitinjangam/user-mgmt-service/internal/auth"
	"golang.org/x/sync/errgroup"
)

//go:generate oapi-codegen -generate types,gin,spec -package api -o api.gen.go api.yaml

type Config struct {
	Port     string
	Services []ServerInterface
}

type Handler struct {
	config Config
	server *http.Server
}

func New(config *Config) (*Handler, error) {
	openapi, err := GetSwagger()
	if err != nil {
		return nil, err
	}

	router := gin.New()

	openapi.Servers = nil

	router.Use(middleware.OapiRequestValidator(openapi))

	router.Use(correlation.TraceMiddleware)

	router.Use(auth.AuthMiddleware)

	for _, service := range config.Services {
		RegisterHandlers(router, service)
	}

	httpServer := &http.Server{
		Handler: router,
		Addr:    config.Port,
	}

	return &Handler{
		server: httpServer,
		config: *config,
	}, nil
}

func (handler *Handler) Run(ctx context.Context) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errWg, errCtx := errgroup.WithContext(ctx)
	// start HTTP server in one goroutine
	errWg.Go(func() error {
		if err := handler.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return err
		}

		return nil
	})

	// listen to SIGTERM on other goroutine
	errWg.Go(func() error {
		<-errCtx.Done()
		return handler.Shutdown()
	})

	// wait until all function calls from the goroutines have returned
	// then returns the first non-nil error (if any) from them.
	err := errWg.Wait()
	if err == context.Canceled || err == nil {
	} else if err != nil {
		return err
	}

	return nil
}

// Shutdown give the HTTP server the order to shut down, and await for 5
// seconds for all connections to gracefully finish
func (handler *Handler) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := handler.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("api: server Shutdown: %w", err)
	}

	<-ctx.Done()

	return nil
}
