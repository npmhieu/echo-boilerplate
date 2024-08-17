package config

import (
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"log"
	"os"
)

var DB *gorm.DB

func Connect() {
	// Retrieve DATABASE_URL from environment variables
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		panic("DATABASE_URL not set in .env file")
	}

	var err error
	DB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to database: " + err.Error())
	}
}

// ConnectDatabase establishes a connection to the MySQL database using GORM
func ConnectDatabase() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatalf("DATABASE_URL not set in .env file")
	}

	var err error
	DB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{
		// Optionally add additional GORM configuration here
		// For example, skip default transaction handling, logging, etc.
	})

	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}

	log.Println("Database connection successfully established")
}

// GetDatabase returns the global database instance
func GetDatabase() *gorm.DB {
	if DB == nil {
		log.Fatal("Database connection is not established")
	}
	return DB
}
