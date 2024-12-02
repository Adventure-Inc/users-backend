package database

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func DatabaseInstance() *mongo.Client {
	mongoDB := "Insert mongo db instance"
	fmt.Print(mongoDB)

	client, err := mongo.NewClient(options.Client().ApplyURI(mongoDB))

	if err != nil {
		log.Fatal("error")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	defer cancel()

	err = client.Connect(ctx)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n connected to mongodb")

	return client

}

var Client *mongo.Client = DatabaseInstance()

func OpenCollection(client *mongo.Client, collectionName string) *mongo.Collection {
	var collection *mongo.Collection = client.Database("users").Collection(collectionName)

	return collection
}
