package service

import (
	"github.com/nitinjangam/user-mgmt-service/internal/config"
	"github.com/nitinjangam/user-mgmt-service/internal/db"
)

// Response represents the standard response format
type Response struct {
	StatusCode int         `json:"status"`
	Data       interface{} `json:"data,omitempty"`
	Message    string      `json:"message,omitempty"`
}

// User represents the requirements of the service
type User struct {
	conf *config.AppConfig
	db   db.Service
}
