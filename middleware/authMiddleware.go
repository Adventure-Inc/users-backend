package middleware

import (
	"fmt"
	"net/http"

	helper "github.com/Adventure-Inc/users-backend/helpers"
	"github.com/gin-gonic/gin"
)

func Authentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientToken := c.Request.Header.Get("Authorization")

		if clientToken == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("No authorization header provided.")})
			c.Abort()
			return
		}

		fmt.Printf("The client token is...... %s: \n", clientToken)

		claims, err := helper.ValidateToken(clientToken)

		if err != "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			c.Abort()
			return
		}

		c.Set("email", claims.Email)
		c.Set("FirstName", claims.FirstName)
		c.Set("LastName", claims.LastName)
		c.Set("uid", claims.Uid)
		c.Next()

	}
}
