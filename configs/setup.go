package configs

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func ConnectDB() *mongo.Client {
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI(GetEnv("MONGODB_URI")).SetServerAPIOptions(serverAPI)

	// Create a new client and connect to the server
	client, err := mongo.Connect(context.TODO(), opts)
	if err != nil {
		// Print the error for debugging purposes, but don't return it
		fmt.Println("Error connecting to the database:", err)
		return nil
	}

	// Send a ping to confirm a successful connection
	if err := client.Database("admin").RunCommand(context.TODO(), bson.D{{"ping", 1}}).Err(); err != nil {
		// Print the error for debugging purposes, but don't return it
		fmt.Println("Error pinging the database:", err)
		return nil
	}

	fmt.Println("Pinged your deployment. You successfully connected to MongoDB!")
	return client
}

// Client instance
var DB *mongo.Client = ConnectDB()

func GetCollection(client *mongo.Client, collectionName string) *mongo.Collection {
	collection := client.Database("GO-PODCAST").Collection(collectionName)
	return collection
}
