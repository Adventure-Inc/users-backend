package main

import (
	"encoding/json"
	"log"
	"os"

	"net/http"

	controller "github.com/Adventure-Inc/users-backend/controllers"
	"github.com/Adventure-Inc/users-backend/middleware"
	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Credentials which stores google ids.
type WebCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type Credentials struct {
	Web WebCredentials `json:"web"`
}

var store = sessions.NewCookieStore([]byte("secret"))
var cred Credentials
var conf *oauth2.Config

func init() {
	file, err := os.ReadFile("./secrets/creds.json")
	if err != nil {
		log.Printf("File error: %v\n", err)
		os.Exit(1)
	}

	if err := json.Unmarshal(file, &cred); err != nil {
		log.Fatalf("Failed to unmarshal credentials: %v\n", err)
	}

	if cred.Web.ClientID == "" || cred.Web.ClientSecret == "" {
		log.Fatalf("Invalid credentials: ClientID or ClientSecret is missing")
	}

	conf = &oauth2.Config{
		ClientID:     cred.Web.ClientID,
		ClientSecret: cred.Web.ClientSecret,
		RedirectURL:  "http://127.0.0.1:9090/auth",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email", // You have to select your own scope from here -> https://developers.google.com/identity/protocols/googlescopes#google_sign-in
		},
		Endpoint: google.Endpoint,
	}

	log.Println("OAuth configuration initialized successfully.")
}

func main() {

	gin.SetMode(gin.ReleaseMode)

	port := os.Getenv("PORT")

	if port == "" {
		port = "8080"
	}

	router := gin.New()
	router.Use(gin.Logger())
	router.Use(sessions.Sessions("goquestsession", store))

	// Landing page route
	router.GET("/home", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Welcome to the Adventure-Inc Users API!",
		})
	})

	// Google auth routes

	googleRoutes := router.Group("/google")
	controller.SetupGoogleRoutes(googleRoutes, conf)

	// public routes do not requrie authentication
	publicRoutes := router.Group("/public")
	{
		publicRoutes.POST("/users/login", controller.Login())
		publicRoutes.POST("/users/signup", controller.SignUp())
	}

	// protected routes require authentication
	protectedRoutes := router.Group("/protected")
	{
		// Add routes that need authentication in this block
		protectedRoutes.GET("/user/:user_id", controller.GetUser())
		protectedRoutes.GET("/users", controller.GetUsers())
	}
	protectedRoutes.Use(middleware.Authentication())

	router.Run(":" + port)

}
