package service

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/nitinjangam/go-utils/logger"
	"github.com/nitinjangam/user-mgmt-service/api"
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

	usr := api.PostAuthLoginJSONRequestBody{}
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
	accessToken, refreshToken, expiryTime, err := auth.GenerateTokens([]byte(u.conf.TokenSecretKey), user.UserID, time.Minute*15)
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

	expiryTimeInt := int(expiryTime.Unix())
	tokenType := "Bearer"

	resp := api.AuthResponse{
		AccessToken:  &accessToken,
		ExpiresIn:    &expiryTimeInt,
		RefreshToken: &refreshToken,
		TokenType:    &tokenType,
	}

	JSONResponse(c, http.StatusOK, resp, headers, "logged in successfully")

}

// Logout the user and invalidate tokens
// (POST /auth/logout)
func (u *User) PostAuthLogout(c *gin.Context) {
	log := logger.FromContext(c.Request.Context())

	log.Info("logout handler called")

	authorizationHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authorizationHeader, "Bearer ") {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header"})
		return
	}
	accessToken := strings.TrimPrefix(authorizationHeader, "Bearer ")

	userID, err := strconv.Atoi(c.GetHeader("user_id"))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user_id"})
		return
	}

	if err = u.db.DeleteTokens(c, uint(userID), accessToken); err != nil {
		log.Error("error while deleteTokens", "error", err.Error())
	}

	c.JSON(http.StatusOK, "User logged out successfully")

}

// Refresh access token using refresh token
// (POST /auth/refresh)
func (u *User) PostAuthRefresh(c *gin.Context) {
	log := logger.FromContext(c.Request.Context())
	log.Info("received refresh token request")

	// Extract the refresh token from the request body
	refTok := api.PostAuthRefreshJSONBody{}
	err := c.ShouldBindJSON(&refTok)
	if err != nil && refTok.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Refresh token not provided"})
		return
	}

	// Verify the refresh token's signature
	refreshTokenClaims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(refTok.RefreshToken, refreshTokenClaims, func(token *jwt.Token) (interface{}, error) {
		JWTSecretKey := os.Getenv("TOKEN_SECRET_KEY")
		return []byte(JWTSecretKey), nil
	})

	if err != nil {
		log.Error(err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	// Extract user ID from refresh token claims (customize as needed)
	userID := uint(refreshTokenClaims["user_id"].(float64))

	// Generate a new access token with a 15-minute expiration
	accessToken, err := auth.GenerateAccessToken([]byte(u.conf.TokenSecretKey), userID, time.Minute*15)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating access token"})
		return
	}

	// update access token in db
	token := db.Token{
		UserID:         userID,
		AccessToken:    accessToken,
		RefreshToken:   refTok.RefreshToken,
		ExpirationTime: time.Now().Add(time.Minute * 15),
	}
	if err = u.db.UpdateAccessToken(c.Request.Context(), &token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating access token"})
		return
	}

	// Return the new access token to the client
	tokenExpiresIn := int(time.Duration(time.Minute * 15))
	tokenType := "Bearer"
	resp := api.AuthResponse{
		AccessToken:  &accessToken,
		ExpiresIn:    &tokenExpiresIn,
		RefreshToken: &refTok.RefreshToken,
		TokenType:    &tokenType,
	}
	c.JSON(http.StatusOK, resp)
}

// Register a new user
// (POST /auth/register)
func (u *User) PostAuthRegister(c *gin.Context) {
	log := logger.FromContext(c.Request.Context())
	log.Info("received register user request")
	usr := api.PostAuthRegisterJSONRequestBody{}
	if err := c.ShouldBindJSON(&usr); err != nil {
		log.Error("registeruser: invalid request body", "error", err)
		JSONResponse(c, http.StatusBadRequest, nil, nil, "invalid request body")
		return
	}

	hashedPassword, err := auth.HashPassword(usr.Password)
	if err != nil {
		log.Error("registeruser: error while hashing password", "error", err)
		JSONResponse(c, http.StatusInternalServerError, nil, nil, "internal server error")
		return
	}

	usrDB := db.User{
		Username:     usr.Username,
		Email:        usr.Email,
		PasswordHash: hashedPassword,
	}

	// TBD implemet username exist, user with same email exist
	err = u.db.RegisterUser(c.Request.Context(), &usrDB)
	if err != nil {
		log.Error("registeruser: internal server error", "error", err)
		JSONResponse(c, http.StatusInternalServerError, nil, nil, "internal server error")
		return
	}

	userIDStr := strconv.Itoa(int(usrDB.UserID))
	resp := api.UserResponse{
		Email:    &usr.Email,
		UserId:   &userIDStr,
		Username: &usr.Username,
	}

	log.Info("user registration successful")

	JSONResponse(c, http.StatusCreated, resp, nil, "user registration done")

}

// Get the authenticated user's profile
// (GET /auth/users/me)
func (u *User) GetAuthUsersMe(c *gin.Context) {}

// JSONResponse builds and sends a JSON response
func JSONResponse(c *gin.Context, statusCode int, data interface{}, headers map[string]string, message string) {

	for header, value := range headers {
		c.Header(header, value)
	}

	response := Response{
		StatusCode: statusCode,
		Data:       data,
		Message:    message,
	}

	c.JSON(statusCode, response)
}
