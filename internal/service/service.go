package service

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/nitinjangam/go-utils/logger"
	"github.com/nitinjangam/user-mgmt-service/internal/auth"
	"github.com/nitinjangam/user-mgmt-service/internal/config"
	"github.com/nitinjangam/user-mgmt-service/internal/db"
)

// New returns a User Service instance
func New(config *config.AppConfig, db db.DbService) *User {
	return &User{
		conf: config,
		db:   db,
	}
}

// Change user's password
// (POST /auth/change-password)
func (u *User) PostAuthChangePassword(c *gin.Context) {

}

// Authenticate user and get an access token
// (POST /auth/login)
func (u *User) PostAuthLogin(c *gin.Context) {
	log := logger.FromContext(c.Request.Context())
	log.Info("received login request")

	usr := loginRequest{}
	if err := c.ShouldBindJSON(&usr); err != nil {
		log.Error("login: invalid request body", "error", err)
		JSONResponse(c, http.StatusBadRequest, nil, nil, "invalid request body")
		return
	}

	// get user details from database
	user, err := u.db.GetUser(c.Request.Context(), usr.Username)
	if err != nil {
		log.Error("login: error while getting user from database", "error", err)
		// TBD check the error and give valid response like internal servr error/invalid creds
		JSONResponse(c, http.StatusUnauthorized, nil, nil, "invalid credentials")
		return
	}

	// check if password matches with records
	if !auth.ValidatePassword(user.PasswordHash, usr.Password) {
		JSONResponse(c, http.StatusUnauthorized, nil, nil, "invalid credentials")
		return
	}

	// Generate tokens
	claims := jwt.MapClaims{
		"user_id": user.UserID,
		"exp":     time.Now().Add(time.Hour * 7).Unix(),
	}
	accessToken, refreshToken, expiryTime, err := auth.GenerateTokens([]byte(u.conf.TokenSecretKey), claims)
	if err != nil {
		log.Error("login: error while generating tokens", "error", err.Error())
		//TBD give correlation id in response as ticket id to trace the error
		JSONResponse(c, http.StatusInternalServerError, nil, nil, "internal server error")
		return
	}

	// Store tokens in database
	token := db.Token{
		UserID:         user.UserID,
		AccessToken:    accessToken,
		RefreshToken:   refreshToken,
		ExpirationTime: expiryTime,
	}
	if err := u.db.StoreTokens(c.Request.Context(), &token); err != nil {
		log.Error("login: error while storing tokens", "error", err.Error())
		//TBD give correlation id in response as ticket id to trace the error
		JSONResponse(c, http.StatusInternalServerError, nil, nil, "internal server error")
		return
	}

	// Inject tokens in headers
	headers := map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expiry_time":   expiryTime.String(),
	}

	JSONResponse(c, http.StatusOK, nil, headers, "logged in successfully")

}

// Logout the user and invalidate tokens
// (POST /auth/logout)
func (u *User) PostAuthLogout(c *gin.Context) {}

// Refresh access token using refresh token
// (POST /auth/refresh)
func (u *User) PostAuthRefresh(c *gin.Context) {}

// Register a new user
// (POST /auth/register)
func (u *User) PostAuthRegister(c *gin.Context) {
	log := logger.FromContext(c.Request.Context())
	log.Info("received register user request")
	usr := db.User{}
	if err := c.ShouldBindJSON(&usr); err != nil {
		log.Error("registeruser: invalid request body", "error", err)
		JSONResponse(c, http.StatusBadRequest, nil, nil, "invalid request body")
		return
	}

	hashedPassword, err := auth.HashPassword(usr.PasswordHash)
	if err != nil {
		log.Error("registeruser: error while hashing password", "error", err)
		JSONResponse(c, http.StatusInternalServerError, nil, nil, "internal server error")
		return
	}

	usr.PasswordHash = hashedPassword

	// TBD implemet username exist, user with same email exist
	err = u.db.RegisterUser(c.Request.Context(), &usr)
	if err != nil {
		log.Error("registeruser: internal server error", "error", err)
		JSONResponse(c, http.StatusInternalServerError, nil, nil, "internal server error")
		return
	}

	//mask password before sending back to user
	usr.PasswordHash = "*******************"

	log.Info("user registration successful")

	JSONResponse(c, http.StatusCreated, usr, nil, "user registration done")

}

// Get the authenticated user's profile
// (GET /auth/users/me)
func (u *User) GetAuthUsersMe(c *gin.Context) {}

// JSONResponse builds and sends a JSON response
func JSONResponse(c *gin.Context, statusCode int, data interface{}, headers map[string]string, message string) {
	if headers != nil {
		for header, value := range headers {
			c.Header(header, value)
		}
	}
	response := Response{
		StatusCode: statusCode,
		Data:       data,
		Message:    message,
	}

	c.JSON(statusCode, response)
}
