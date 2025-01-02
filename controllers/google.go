package controllers

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	helper "github.com/Adventure-Inc/users-backend/helpers"
	model "github.com/Adventure-Inc/users-backend/models"
	"go.mongodb.org/mongo-driver/bson/primitive"
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
		RedirectURL:  "http://localhost:8000/google/auth/google/callback",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile", // We can select more scopes from here -> https://developers.google.com/identity/protocols/googlescopes#google_sign-in
		},
		Endpoint: google.Endpoint,
	}

	log.Println("OAuth configuration initialized successfully.")
}

var oauthStateStringGl = os.Getenv("STATE")

/*
InitializeOAuthGoogle Function
*/
func InitializeOAuthGoogle() gin.HandlerFunc {
	return func(c *gin.Context) {
		oauthStateStringGl = viper.GetString("STATE")
		c.Next() // Call the next handler in the chain
	}
}

/*
HandleGoogleLogin Function
*/
func HandleGoogleLogin() gin.HandlerFunc {
	return func(c *gin.Context) {
		HandleLogin(c.Writer, c.Request, conf, oauthStateStringGl)
	}
}

func GenerateRandomPassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal(err)
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}

/*
CallBackFromGoogle Function
*/
func CallBackFromGoogle() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Printf("Callback-gl..")

		state := c.Query("state")

		if state != oauthStateStringGl {
			log.Println("invalid oauth state expected" + oauthStateStringGl + ", got" + state + "\n")
			c.Redirect(http.StatusTemporaryRedirect, "/")
			return
		}

		code := c.Query("code")

		if code == "" {
			log.Println("Code not found")
			c.String(http.StatusBadRequest, "Code Not Found to provide AccessToken..\n")
			reason := c.Query("error_reason")
			if reason == "user_denied" {
				c.String(http.StatusForbidden, "User has denied Permission..")
			}
		} else {
			token, err := conf.Exchange(oauth2.NoContext, code)
			if err != nil {
				log.Println("conf.Exchange() failed with " + err.Error() + "\n")
				return
			}

			log.Println("TOKEN>> AccessToken>> " + token.AccessToken)
			log.Println("TOKEN>> Expiration Time>> " + token.Expiry.String())
			log.Println("TOKEN>> RefreshToken>> " + token.RefreshToken)

			resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + url.QueryEscape(token.AccessToken))
			if err != nil {
				log.Println("Get: " + err.Error() + "\n")
				c.Redirect(http.StatusTemporaryRedirect, "/")
				return
			}
			defer resp.Body.Close()

			response, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Println("ReadAll: " + err.Error() + "\n")
				c.Redirect(http.StatusTemporaryRedirect, "/")
				return
			}

			type googleUser struct {
				ID           primitive.ObjectID `bson:"_id"`
				Email        string             `json:"email"`
				FirstName    string             `json:"given_name"`
				LastName     string             `json:"family_name"`
				UserId       string             `json:"id"`
				Password     *string            `json:"password" validate:"min=6"`
				Avatar       *string            `json:"avatar"`
				Phone        *string            `json:"phone"`
				Token        *string            `json:"token"`
				RefreshToken *string            `json:"refresh_token"`
				Created_at   time.Time          `json:"created_at"`
				Updated_at   time.Time          `json:"updated_at"`
			}

			var user googleUser

			err = json.Unmarshal(response, &user)
			if err != nil {
				log.Println("Failed to unmarshal user info: ", err)
				c.Redirect(http.StatusTemporaryRedirect, "/")
				return
			}

			var foundUser model.User

			var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
			defer cancel()

			err = userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
			if err != nil {
				log.Println("user not found: ", err)
				log.Println("Creating a new user")

				randomPassword := GenerateRandomPassword(12) // Generate a random password of length 12
				password := HashPassword(randomPassword)
				user.Password = &password

				user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
				user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
				user.ID = primitive.NewObjectID()
				user.UserId = user.ID.Hex()

				validationErr := validate.Struct(user)
				if validationErr != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
					return
				}

				token, refreshToken, _ := helper.GenerateAllTokens(user.Email, user.FirstName, user.LastName, user.UserId)
				user.Token = &token
				user.RefreshToken = &refreshToken

				resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
				if insertErr != nil {
					msg := "user item was not created"
					c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
					return
				}

				log.Println("Inserted new user:", resultInsertionNumber)

				c.JSON(http.StatusOK, user)
			} else {
				// User found, update the tokens
				signedToken, signedRefreshToken, err := helper.GenerateAllTokens(user.Email, user.FirstName, user.LastName, foundUser.User_id)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
					return
				}

				// Update the tokens in your database or wherever necessary
				helper.UpdateAllTokens(signedToken, signedRefreshToken, user.UserId)

				c.JSON(http.StatusOK, user)
			}
		}
	}
}
