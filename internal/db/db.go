package db

import (
	"context"
	"fmt"
	"log"

	"github.com/nitinjangam/go-utils/logger"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type DBConfig struct {
	DBHost     string `json:"DB_HOST" envconfig:"DB_HOST"`
	DBPort     string `json:"DB_PORT" envconfig:"DB_PORT"`
	DBName     string `json:"DB_NAME" envconfig:"DB_NAME"`
	DBUser     string `json:"DB_USER" envconfig:"DB_USER"`
	DBPassword string `json:"DB_PASSWORD" envconfig:"DB_PASSWORD"`
	DBSslMode  string `json:"DB_SSL_MODE" envconfig:"DB_SSL_MODE"`
}

type DB struct {
	Conn *gorm.DB
	User User
}

type DbService interface {
	ChangePassword(ctx context.Context)
	Login(ctx context.Context)
	Logout(ctx context.Context)
	RefreshToken(ctx context.Context)
	RegisterUser(ctx context.Context, usr *User) error
	GetUser(ctx context.Context, username string) (*User, error)
	StoreTokens(ctx context.Context, tokens *Token) error
	UpdateAccessToken(ctx context.Context, tokens *Token) error
	DeleteTokens(ctx context.Context, userID uint, accessToken string) error
	GetAuthUsersMe(ctx context.Context)
	CloseConn(ctx context.Context)
}

func New(ctx context.Context, conf *DBConfig) DbService {
	// Construct the connection string
	connStr := fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s sslmode=%s",
		conf.DBHost, conf.DBPort, conf.DBName, conf.DBUser, conf.DBPassword, conf.DBSslMode)

	// Open a database connection
	db, err := gorm.Open(postgres.Open(connStr), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	return &DB{
		Conn: db,
	}
}

func (db *DB) ChangePassword(ctx context.Context) {

}

func (db *DB) Login(ctx context.Context) {

}

func (db *DB) Logout(ctx context.Context) {

}

func (db *DB) RefreshToken(ctx context.Context) {

}

func (db *DB) RegisterUser(ctx context.Context, usr *User) error {
	log := logger.FromContext(ctx)

	tx := db.Conn.Create(usr)
	if tx.Error != nil {
		log.Error("error while creating user in db", "error", tx.Error.Error())
		return tx.Error
	}

	return nil
}

func (db *DB) GetAuthUsersMe(ctx context.Context) {

}

func (db *DB) CloseConn(ctx context.Context) {

}

func (db *DB) GetUser(ctx context.Context, username string) (*User, error) {
	log := logger.FromContext(ctx)

	user := User{}
	if err := db.Conn.Where("username = ?", username).First(&user).Error; err != nil {
		log.Error("error while getting user from database", "error", err.Error())
		return nil, err
	}

	return &user, nil
}

func (db *DB) StoreTokens(ctx context.Context, tokens *Token) error {
	log := logger.FromContext(ctx)

	tx := db.Conn.Create(tokens)
	if tx.Error != nil {
		log.Error("error while storing tokens in db", "error", tx.Error.Error())
		return tx.Error
	}

	return nil

}

func (db *DB) UpdateAccessToken(ctx context.Context, tokens *Token) error {
	log := logger.FromContext(ctx)
	tx := db.Conn.Table("tokens").Where("user_id = ?", tokens.UserID).Where("refresh_token = ?", tokens.RefreshToken).Update("access_token", tokens.AccessToken).Update("expiration_time", tokens.ExpirationTime)
	if tx.Error != nil {
		log.Error("error while updating access token in db", "error", tx.Error.Error())
		return tx.Error
	}
	if tx.RowsAffected == 0 {
		log.Error("error while updating access token in db", "error", fmt.Errorf("refresh token not found in db"))
		return fmt.Errorf("no refresh token found in db")
	}
	return nil
}

func (db *DB) DeleteTokens(ctx context.Context, userID uint, accessToken string) error {
	log := logger.FromContext(ctx)
	tok := Token{}
	tx := db.Conn.Table("tokens").Where("user_id = ?", userID).Where("access_token = ?", accessToken).Delete(&tok)
	if tx.Error != nil {
		log.Error("error while deleting tokens from db", "error", tx.Error.Error())
		return tx.Error
	}
	if tx.RowsAffected == 0 {
		log.Error("error while deleting tokens from db", "error", fmt.Errorf("access token not found in db"))
		return fmt.Errorf("no refresh token found in db")
	}
	return nil
}
