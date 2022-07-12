package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path"

	"github.com/gin-gonic/gin"
	"github.com/zalando/gin-oauth2/azure"
)

var redirectURL, credFile string

func init() {
	bin := path.Base(os.Args[0])
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
Usage of %s
================
`, bin)
		flag.PrintDefaults()
	}
	flag.StringVar(&redirectURL, "redirect", "http://localhost:8081/auth/", "URL to be redirected to after authorization.")
	//flag.StringVar(&credFile, "cred-file", "./example/azure/test-clientid.azure.json", "Credential JSON file")
	flag.StringVar(&credFile, "cred-file", "./ignoreme.creds.azure.json", "Credential JSON file")
}
func main() {
	flag.Parse()

	//  azure scopes:
	//  https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent
	scopes := []string{
		"User.Read",
	}
	secret := []byte("secret")
	sessionName := "goquestsession"
	router := gin.Default()
	// init settings for azure auth
	azure.Setup(redirectURL, credFile, scopes, secret)
	router.Use(azure.Session(sessionName))

	router.GET("/login", azure.LoginHandler)

	// protected url group
	private := router.Group("/auth")
	private.Use(azure.Auth())
	private.GET("/", UserInfoHandler)
	private.GET("/api", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{"message": "Hello from private for groups"})
	})

	router.Run("127.0.0.1:8081")
}

func UserInfoHandler(ctx *gin.Context) {
	var (
		res azure.AuthUser
		val interface{}
		ok  bool
	)

	val = ctx.MustGet("user")
	if res, ok = val.(azure.AuthUser); !ok {
		res = azure.AuthUser{
			Name: "no User",
		}
	}
	ctx.JSON(http.StatusOK, gin.H{"Hello": "from private", "user": res})
}
