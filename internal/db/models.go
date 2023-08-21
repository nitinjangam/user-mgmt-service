package db

import (
	"time"
)

type User struct {
	UserID       uint   `gorm:"primaryKey"`
	Username     string `json:"username"`
	Email        string `json:"email"`
	PasswordHash string `json:"password"`
}

type Token struct {
	UserID         uint
	AccessToken    string
	RefreshToken   string `json:"refresh_token"`
	ExpirationTime time.Time
}

type UserResponse struct {
	UserID   uint   `gorm:"primaryKey"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string
}
