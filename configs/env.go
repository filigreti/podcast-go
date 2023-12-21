package configs

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

func GetEnv(key string, defaultValue string) string {
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found or cannot be loaded. Using default values.")
		return defaultValue
	}

	value := os.Getenv(key)
	if value == "" {
		log.Printf("Warning: Environment variable %s is not set. Using default value.\n", key)
		return defaultValue
	}

	return value
}
