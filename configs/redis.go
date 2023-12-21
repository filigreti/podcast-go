package configs

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

var RedisClient *redis.Client = ConnectRedis()

func ConnectRedis() *redis.Client {
	options := &redis.Options{
		Addr:     GetEnv("REDIS_ADDR"),
		Password: GetEnv("REDIS_PASSWORD"),
		DB:       0,
	}
	client := redis.NewClient(options)

	// Ping the Redis server to check the connection
	pong, err := client.Ping(context.Background()).Result()
	if err != nil {
		// Print the error for debuggings purposes, but don't return it
		fmt.Println("Error connecting to Redis:", err)
		return nil
	}

	fmt.Println("Ping response from Redis:", pong)
	return client
}

func GetRedisClient() *redis.Client {
	return RedisClient
}
