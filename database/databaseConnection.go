package database

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func DatabaseInstance() *mongo.Client {
	// Create a context with a timeout and a cancel function
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel() // Ensure cancel is called to release resources

	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI("mongodb+srv://chiefdivine:adventures@adventurecluster.f2cyp.mongodb.net/?retryWrites=true&w=majority&appName=AdventureCluster").SetServerAPIOptions(serverAPI)
	client, _ := mongo.Connect(ctx, opts) // Use ctx here

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
