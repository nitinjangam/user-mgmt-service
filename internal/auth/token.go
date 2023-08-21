package auth

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

const (
	AuthorizationHeader = "Authorization"
	BearerPrefix        = "Bearer "
	JWTSecretKey        = "your-secret-key"
)

func AuthMiddleware(c *gin.Context) {

	// Exclude specific routes from middleware
	if c.FullPath() == "/auth/register" || c.FullPath() == "/auth/login" || c.FullPath() == "/auth/refresh" {
		c.Next()
		return
	}

	// Get the token from the Authorization header
	authHeader := c.GetHeader(AuthorizationHeader)
	if authHeader == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Check if the Authorization header has the Bearer prefix
	if !strings.HasPrefix(authHeader, BearerPrefix) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, BearerPrefix)

	// Parse and verify the JWT token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(JWTSecretKey), nil
	})

	if err != nil || !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// Token is valid, continue to the next middleware or handler
	c.Next()
}

func GenerateTokens(secretKey []byte, claims jwt.MapClaims) (string, string, time.Time, error) {
	// generate JWT token based on claims and secret key provided
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", "", time.Now(), err
	}

	// generate refresh token
	const refreshTokenLength = 32

	refreshTokenBytes := make([]byte, refreshTokenLength)
	_, err = rand.Read(refreshTokenBytes)
	if err != nil {
		// Handle error
		return "", "", time.Now(), err
	}
	refreshToken := base64.URLEncoding.EncodeToString(refreshTokenBytes)

	// set refresh token expiry time
	refreshTokenExpiry := time.Now().Add(time.Hour)

	return tokenString, refreshToken, refreshTokenExpiry, nil
}
