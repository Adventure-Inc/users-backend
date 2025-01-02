package main

import (
	"os"

	"net/http"

	controller "github.com/Adventure-Inc/users-backend/controllers"
	"github.com/Adventure-Inc/users-backend/middleware"
	"github.com/gin-gonic/gin"
)

// Credentials which stores google ids.
type WebCredentials struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURL  []string `json:"redirect_uris"`
}

type Credentials struct {
	Web WebCredentials `json:"web"`
}

func main() {

	gin.SetMode(gin.ReleaseMode)

	port := os.Getenv("PORT")

	if port == "" {
		port = "8000"
	}

	router := gin.New()
	router.Use(gin.Logger())
	// router.Use(sessions.Sessions("goquestsession", store))

	// Landing page route
	router.LoadHTMLFiles("client/index.html")
	router.GET("/home", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"title":   "Adventure-Inc Users API",
			"message": "Welcome to the Adventure-Inc Users API!",
		})
	})

	// Google auth routes
	googleRoutes := router.Group("/google")
	{
		googleRoutes.GET("/auth", controller.InitializeOAuthGoogle())
		googleRoutes.GET("/auth/google/login", controller.HandleGoogleLogin())
		googleRoutes.GET("/auth/google/callback", controller.CallBackFromGoogle())
	}

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
