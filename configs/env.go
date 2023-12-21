package configs

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

func GetEnv(key string) string {
	if os.Getenv("ENVIRONMENT") == "production" {
		// In production, directly use environment variables without loading from file
		return os.Getenv(key)
	}

	// For non-production environments, attempt to load from the .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	return os.Getenv(key)
}
