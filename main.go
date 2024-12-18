package main

import (
	"os"

	controller "github.com/Adventure-Inc/users-backend/controllers"
	"github.com/Adventure-Inc/users-backend/middleware"
	"github.com/gin-gonic/gin"
)

func main() {

	gin.SetMode(gin.ReleaseMode)

	port := os.Getenv("PORT")

	if port == "" {
		port = "8080"
	}

	router := gin.New()
	router.Use(gin.Logger())

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
