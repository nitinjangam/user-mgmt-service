package auth

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/golang-jwt/jwt"
)

const (
	AuthorizationHeader = "Authorization"
	BearerPrefix        = "Bearer "
)

func AuthenticationFunc1(c context.Context, input *openapi3filter.AuthenticationInput) error {
	// extract Authorization token from header
	authorizationHeader := input.RequestValidationInput.Request.Header.Get("Authorization")
	if authorizationHeader == "" {
		return &openapi3filter.SecurityRequirementsError{
			SecurityRequirements: *input.RequestValidationInput.Route.Operation.Security,
			Errors:               []error{errors.New("Missing authorization header")},
		}
	}

	// check that token is of Bearer type
	if !strings.HasPrefix(authorizationHeader, "Bearer ") {
		return &openapi3filter.SecurityRequirementsError{
			SecurityRequirements: *input.RequestValidationInput.Route.Operation.Security,
			Errors:               []error{errors.New("Invalid authorization header")},
		}
	}

	tokenString := strings.TrimPrefix(authorizationHeader, "Bearer ")

	// parse token for validation
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		JWTSecretKey := os.Getenv("TOKEN_SECRET_KEY")
		return []byte(JWTSecretKey), nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return &openapi3filter.SecurityRequirementsError{
				SecurityRequirements: *input.RequestValidationInput.Route.Operation.Security,
				Errors:               []error{errors.New("Invalid token signature")},
			}
		}
		return &openapi3filter.SecurityRequirementsError{
			SecurityRequirements: *input.RequestValidationInput.Route.Operation.Security,
			Errors:               []error{errors.New("Invalid token")},
		}
	}

	//check if token is valid
	if !token.Valid {
		return &openapi3filter.SecurityRequirementsError{
			SecurityRequirements: *input.RequestValidationInput.Route.Operation.Security,
			Errors:               []error{errors.New("Token is invalid")},
		}
	}

	// extract claims from the token
	claims := token.Claims
	mapClaims := claims.(jwt.MapClaims)
	// Check if the token has expired
	if !mapClaims.VerifyExpiresAt(time.Now().Unix(), true) {
		return &openapi3filter.SecurityRequirementsError{
			SecurityRequirements: *input.RequestValidationInput.Route.Operation.Security,
			Errors:               []error{errors.New("Token has expired")},
		}
	}

	//set request header with user_id
	input.RequestValidationInput.Request.Header.Set("user_id", strconv.Itoa(int(mapClaims["user_id"].(float64))))

	return nil
}

// func AuthenticationFunc() gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		// Exclude specific routes from middleware
// 		if c.FullPath() == "/auth/register" || c.FullPath() == "/auth/login" || c.FullPath() == "/auth/refresh" {
// 			c.Next()
// 			return
// 		}

// 		// Get the token from the Authorization header
// 		authorizationHeader := c.GetHeader("Authorization")
// 		if authorizationHeader == "" {
// 			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing authorization header"})
// 			return
// 		}

// 		if !strings.HasPrefix(authorizationHeader, "Bearer ") {
// 			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header"})
// 			return
// 		}

// 		tokenString := strings.TrimPrefix(authorizationHeader, "Bearer ")

// 		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
// 			JWTSecretKey := os.Getenv("TOKEN_SECRET_KEY")
// 			return []byte(JWTSecretKey), nil
// 		})

// 		log.Printf("token %+v", token)

// 		if err != nil {
// 			if err == jwt.ErrSignatureInvalid {
// 				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token signature"})
// 				return
// 			}
// 			log.Printf("token parsing error: %v", err)
// 			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
// 			return
// 		}

// 		if !token.Valid {
// 			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token is invalid"})
// 			return
// 		}

// 		claims := token.Claims

// 		log.Printf("claims from tokenL %+v", claims)
// 		mapClaims := claims.(jwt.MapClaims)
// 		// Check if the token has expired
// 		if !mapClaims.VerifyExpiresAt(time.Now().Unix(), true) {
// 			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token has expired"})
// 			return
// 		}

// 		log.Println("token is valid")

// 		c.Set("user_id", int(mapClaims["user_id"].(float64)))

// 		c.Next()
// 	}
// }

func GenerateTokens(secretKey []byte, userID uint, expiresIn time.Duration) (string, string, time.Time, error) {

	//generate access token
	tokenString, err := GenerateAccessToken(secretKey, userID, expiresIn)
	if err != nil {
		return "", "", time.Now(), err
	}

	// set refresh token expiry time
	refreshTokenExpiry := time.Now().Add(time.Minute * 30)

	// generate refresh token
	refreshToken, err := GenerateRefreshToken(secretKey, userID, refreshTokenExpiry)
	if err != nil {
		return "", "", time.Now(), err
	}

	return tokenString, refreshToken, refreshTokenExpiry, nil
}

func GenerateAccessToken(secretKey []byte, userID uint, expiresIn time.Duration) (string, error) {

	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(expiresIn).Unix(),
	}

	// generate JWT token based on claims and secret key provided
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func GenerateRefreshToken(secretKey []byte, userID uint, expiry time.Time) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     expiry.Unix(),
	}

	// generate JWT token based on claims and secret key provided
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
