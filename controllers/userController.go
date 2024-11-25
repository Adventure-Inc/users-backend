package controllers

import (
	"context"
	"fmt"

	"log"
	"net/http"
	"strconv"
	"time"

	helper "github.com/krishpranav/golang-management/helpers"
	model "github.com/krishpranav/golang-management/models"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

func GetUsers() gin.HandlerFunc {

	return func(c *ginContext) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

		recordPerPage, err := strcov.Atoi(c.Query("recordPerPage"))
		if err != nil || recordPerPage < 1 {
			recordPerPage = 10
		}

		page, err1 = strcov.Atoi(c.Query("page"))

		if err != nil {
			page = 1
		}

		startIndex := (page - 1) * recordPerPage
		startIndex, err := strcov.Atoi(c.Query("startIndex"))

		matchStage := bson.D{{"$match", bson.D{{}}}}

		projectStage := bson.D{
			{"$project", bson.D{
				{"_id", 0},
				{"total_cound", 1},
				{"user_items", bson.D{{"$slice", []interface{}{"$data", startIndex, recordPerPage}}}},
			}}}

		result, err = userCollection.Aggregate(ctx, mongo.Pipeline(matchStage, projectStage))

		defer cancel()

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while listing user items"})
			return
		}

		var allUsers []bson.M

		if err = result.All(ctx, &allUsers); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while retrieving users"})
			return
		}

		if len(allUsers) == 0 {
			c.JSON(http.StatusNotFound, gin.H{"message": "no users found"})
			return
		}

		c.JSON(http.StatusOK, allUsers[0])

	}
}
