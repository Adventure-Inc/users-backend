package database

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func DatabaseInstance() *mongo.Client {
	// Create a context with a timeout and a cancel function
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel() // Ensure cancel is called to release resources

	err := godotenv.Load() // Load the .env file
	if err != nil {
		fmt.Println("Error loading .env file")
	}

	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	uri := os.Getenv("MONGODB_URI") // Get the MongoDB URI from the environment variable
	if uri == "" {
		panic("MONGODB_URI environment variable is not set") // Panic with a clear message if the URI is not set
	}
	opts := options.Client().ApplyURI(uri).SetServerAPIOptions(serverAPI) // Use the retrieved URI
	client, _ := mongo.Connect(ctx, opts)                                 // Use ctx here

	// Send a ping to confirm a successful connection
	if err := client.Database("admin").RunCommand(ctx, bson.D{{Key: "ping", Value: 1}}).Err(); err != nil {
		panic(err)
	}
	fmt.Println("Pinged your deployment. You successfully connected to MongoDB!")

	fmt.Println("\n connected to mongodb")

	return client
}

var Client *mongo.Client = DatabaseInstance()

func OpenCollection(client *mongo.Client, collectionName string) *mongo.Collection {
	var collection *mongo.Collection = client.Database("adventures").Collection(collectionName)

	return collection
}
