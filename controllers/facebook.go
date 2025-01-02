package controllers

import (
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

var oauthStateStringFb = ""

/*
InitializeOAuthFacebook Function
*/
func InitializeOAuthFacebook() {
	oauthStateStringFb = viper.GetString("oauthStateString")
}

/*
HandleFacebookLogin Function
*/
func HandleFacebookLogin(w http.ResponseWriter, r *http.Request) {
	HandleLogin(w, r, conf, oauthStateStringFb)
}

/*
CallBackFromFacebook Function
*/
func CallBackFromFacebook(w http.ResponseWriter, r *http.Request) {
	log.Println("Callback-fb..")

	state := r.FormValue("state")
	log.Println(state)
	if state != oauthStateStringFb {
		log.Println("invalid oauth state, expected " + oauthStateStringFb + ", got " + state + "\n")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")
	log.Println(code)

	if code == "" {
		log.Println("Code not found..")
		w.Write([]byte("Code Not Found to provide AccessToken..\n"))
		reason := r.FormValue("error_reason")
		if reason == "user_denied" {
			w.Write([]byte("User has denied Permission.."))
		}
		// User has denied access..
		// http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	} else {
		token, err := conf.Exchange(oauth2.NoContext, code)
		if err != nil {
			log.Println("conf.Exchange() failed with " + err.Error() + "\n")
			return
		}
		log.Println("TOKEN>> AccessToken>> " + token.AccessToken)
		log.Println("TOKEN>> Expiration Time>> " + token.Expiry.String())
		log.Println("TOKEN>> RefreshToken>> " + token.RefreshToken)

		log.Println("https://graph.facebook.com/me?access_token=" + url.QueryEscape(token.AccessToken) + "&fields=email")
		resp, err := http.Get("https://graph.facebook.com/me?access_token=" +
			url.QueryEscape(token.AccessToken) + "&fields=email")
		if err != nil {
			log.Println("Get: " + err.Error() + "\n")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		defer resp.Body.Close()

		response, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Println("ReadAll: " + err.Error() + "\n")
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		log.Println("parseResponseBody: " + string(response) + "\n")

		w.Write([]byte("Hello, I'm protected\n"))
		w.Write([]byte(string(response)))
		return
	}
}
