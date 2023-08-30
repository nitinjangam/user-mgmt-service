package config

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/nitinjangam/go-utils/logger"
	"github.com/nitinjangam/user-mgmt-service/internal/db"
	"golang.org/x/exp/slog"
)

type AppConfig struct {
	ServiceName    string        `json:"SERVICE_NAME" envconfig:"SERVICE_NAME"`
	ProjectID      string        `json:"PROJECT_ID" envconfig:"PROJECT_ID"`
	Environment    string        `json:"ENVIRONMENT" envconfig:"ENVIRONMENT"`
	Port           string        `json:"PORT" envconfig:"PORT"`
	Host           string        `json:"HOST" envconfig:"HOST"`
	HttpTimeout    time.Duration `json:"HTTP_TIMEOUT" envconfig:"HTTP_TIMEOUT"`
	LogLevel       string        `json:"LOG_LEVEL" envconfig:"LOG_LEVEL"`
	DBConfig       db.Config     `json:"DB_CONFIG" envconfig:"DB_CONFIG"`
	TokenSecretKey string        `json:"TOKEN_SECRET_KEY" envconfig:"TOKEN_SECRET_KEY"`
	Logger         *slog.Logger
}

func (c *AppConfig) InitLogger(ctx context.Context) {
	logger.Init(c.Logger)
}

func New() *AppConfig {
	cfg := newDefaultConfig()

	if err := envconfig.Process("", &cfg); err != nil {
		cfg.Logger.Error("error while processing config using environment variables, trying to build config from json file", "error", err)

		err := cfg.readConfigFromLocalFile("./config/locals.json")
		if err != nil {
			cfg.Logger.Error("error while building config through local file", "error", err)
			return nil
		}
	}

	return &cfg
}

func newDefaultConfig() AppConfig {

	return AppConfig{
		Environment: "Dev",
		Port:        "9999",
		Host:        "localhost",
		HttpTimeout: 60 * time.Second,
		Logger:      slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
}

func (c *AppConfig) readConfigFromLocalFile(filePath string) error {
	//open local configuration file
	fl, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("error while opening local file to read configuration: %v", err)
	}
	defer fl.Close()

	//read data from file
	bt, err := io.ReadAll(fl)
	if err != nil {
		return fmt.Errorf("error while reading local file to read configuration: %v", err)
	}

	//prepare config from the file data
	if err := json.Unmarshal(bt, c); err != nil {
		return fmt.Errorf("error while converting jsondata to config: %v", err)
	}

	return nil
}
