package controllers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/Adventure-Inc/users-backend/database"
	"golang.org/x/crypto/bcrypt"

	helper "github.com/Adventure-Inc/users-backend/helpers"
	model "github.com/Adventure-Inc/users-backend/models"

	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/oauth2"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "users")
var validate = validator.New()
var conf *oauth2.Config
var state string

func randToken() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)

	if err != nil {
		log.Panic("Failed to generate random bytes for auth token")
	}
	return base64.StdEncoding.EncodeToString(b)
}

func getLoginURL(state string) string {
	return conf.AuthCodeURL(state)
}

func SetupGoogleRoutes(group *gin.RouterGroup, conf *oauth2.Config) {
	// Login route
	group.GET("/auth/google/login", func(c *gin.Context) {
		url := conf.AuthCodeURL(state, oauth2.AccessTypeOffline)
		c.Redirect(http.StatusTemporaryRedirect, url)
	})

	// Callback route
	group.GET("/auth/google/callback", func(c *gin.Context) {

		session := sessions.Default(c)
		retrievedState := session.Get("state")

		if retrievedState != c.Query("state") {
			c.AbortWithError(http.StatusUnauthorized, fmt.Errorf("Invalid session state: %s", retrievedState))
			return
		}

		code := c.Query("code")
		if code == "" {
			log.Println("No authorization code provided")
			c.JSON(http.StatusBadRequest, gin.H{"error": "No authorization code provided"})
			return
		}

		// Exchange the authorization code for an access token
		token, err := conf.Exchange(context.Background(), code)
		if err != nil {
			log.Println("Error while exchanging code for token:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange code for token"})
			return
		}

		// Retrieve user information from Google
		client := conf.Client(context.Background(), token)

		resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)

		if err != nil {
			log.Println("Failed to retrieve user information:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user information"})
			return
		}
		defer resp.Body.Close()

		var userInfo map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
			log.Println("Failed to decode user information:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode user information"})
			return
		}

		email := userInfo["email"].(string)
		name := userInfo["name"].(string)

		// Optionally, store or create a user record in the database
		log.Println("User info:", userInfo)

		// Respond with a success message or redirect to a protected page
		c.JSON(http.StatusOK, gin.H{
			"message": "Login successful",
			"name":    name,
			"email":   email,
		})
	})
}

func GetGoogleLogin() gin.HandlerFunc {

	return func(c *gin.Context) {

		if conf == nil {
			log.Println("OAuth2 configuration is not initialized.")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "OAuth2 configuration error"})
			return
		}

		state := randToken()
		session := sessions.Default(c)
		session.Set("state", state)
		if err := session.Save(); err != nil {
			log.Println("Failed to save session:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
			return
		}

		loginURL := getLoginURL(state)
		c.Writer.Write([]byte(`
            <html>
                <title>Golang Google</title>
                <body>
                    <a href='` + loginURL + `'><button>Login with Google!</button></a>
                </body>
            </html>
        `))
	}
}

func GetUsers() gin.HandlerFunc {

	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

		recordPerPage, err := strconv.Atoi(c.Query("recordPerPage"))
		if err != nil || recordPerPage < 1 {
			recordPerPage = 10
		}

		matchStage := bson.D{
			{Key: "$match", Value: bson.D{}},
		}

		projectStage := bson.D{
			{Key: "$project", Value: bson.D{
				{Key: "_id", Value: 0},
				{Key: "firstname", Value: 1},
				{Key: "lastname", Value: 1},
				{Key: "email", Value: 1},
			}},
		}

		result, err := userCollection.Aggregate(ctx, mongo.Pipeline{
			matchStage,
			projectStage,
		})

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

		c.JSON(http.StatusOK, allUsers)

	}
}

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {

		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		userId := c.Param("user_id")

		var user model.User

		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)

		defer cancel()

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "An error occurred while listing user items"})
			return
		}

		c.JSON(http.StatusOK, user)
	}
}

func SignUp() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var user model.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		fmt.Sprintln("Validating the user struct")

		// Validate request based on User struct
		validationErr := validate.Struct(user)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
			return
		}

		fmt.Sprintln("Validated the user struct")

		_, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})

		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for the email"})
			return
		}

		password := HashPassword(*user.Password)
		user.Password = &password

		count, err1 := userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})

		if err1 != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for the phone number"})
			return
		}

		if count > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "this email or phone number already exists"})
			return
		}

		user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.ID = primitive.NewObjectID()
		user.User_id = user.ID.Hex()

		token, refreshToken, _ := helper.GenerateAllTokens(*user.Email, *user.FirstName, *user.LastName, user.User_id)
		user.Token = &token
		user.RefreshToken = &refreshToken

		resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			msg := "user item was not created"
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}
		defer cancel()

		c.JSON(http.StatusOK, resultInsertionNumber)
	}
}

func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		fmt.Printf("About to login")
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		var user model.User
		var foundUser model.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user not found, login seems to be incorrect"})
			return
		}

		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)

		if !passwordIsValid {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		token, refreshToken, _ := helper.GenerateAllTokens(*foundUser.Email, *foundUser.FirstName, *foundUser.LastName, foundUser.User_id)

		helper.UpdateAllTokens(token, refreshToken, foundUser.User_id)
		c.JSON(http.StatusOK, foundUser)

	}
}

func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)

	if err != nil {
		log.Panic(err)
	}

	return string(bytes)
}

func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""

	if err != nil {
		msg = "login or password is incorrect"
		check = false
	}

	return check, msg
}
