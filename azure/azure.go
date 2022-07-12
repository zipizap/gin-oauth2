// Package azure provides you access to AzureActiveDirectory's OAuth2
//
// Refs - Lots of usefull info in:
//
// [1] Microsoft identity platform and OAuth 2.0 authorization code flow
//     Authorization grant description, step-by-step, with indications of parameters
//     https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow#request-an-authorization-code
//
package azure

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/golang/glog"
	"github.com/jmespath/go-jmespath"

	"golang.org/x/oauth2"

	"gopkg.in/square/go-jose.v2/jwt"
	//	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
)

// Credentials stores google client-ids.
type Credentials struct {
	ClientID     string `json:"clientid"`
	ClientSecret string `json:"secret"`
	TenantId     string `json:"tenantId"`
}

var (
	conf  *oauth2.Config
	cred  Credentials
	state string
	store sessions.CookieStore
)

func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		glog.Fatalf("[Gin-OAuth] Failed to read rand: %v\n", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// scopes will be added
func Setup(redirectURL, credFile string, scopes []string, secret []byte) {
	// append into scopes the Directory.Read.All required for getGroupsOfThisUser()
	scopes = append(scopes, "Directory.Read.All")
	store = sessions.NewCookieStore(secret)
	var c Credentials
	file, err := os.ReadFile(credFile)
	if err != nil {
		glog.Fatalf("[Gin-OAuth] File error: %v\n", err)
	}
	err = json.Unmarshal(file, &c)
	if err != nil {
		glog.Fatalf("[Gin-OAuth] Failed to unmarshal client credentials: %v\n", err)
	}
	azureOauth2Endpoint := oauth2.Endpoint{
		AuthURL:  "https://login.microsoftonline.com/" + c.TenantId + "/oauth2/v2.0/authorize",
		TokenURL: "https://login.microsoftonline.com/" + c.TenantId + "/oauth2/v2.0/token",
	}
	conf = &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint:     azureOauth2Endpoint,
	}
}

func Session(name string) gin.HandlerFunc {
	return sessions.Sessions(name, store)
}

func LoginHandler(ctx *gin.Context) {
	state = randToken()
	session := sessions.Default(ctx)
	session.Set("state", state)
	session.Save()
	ctx.Writer.Write([]byte("<html><title>Login via Azure</title> <body> <a href='" + GetLoginURL(state) + "'><button>Login with Azure!</button> </a> </body></html>"))
}

func GetLoginURL(state string) string {
	return conf.AuthCodeURL(state)
}

type AuthUser struct {
	Login   string   `json:"login"`
	Name    string   `json:"name"`
	Email   string   `json:"email"`
	Company string   `json:"company"`
	URL     string   `json:"url"`
	Groups  []string `json:"groups"`
}

func init() {
	gob.Register(AuthUser{})
}

func Auth() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var (
			ok       bool
			authUser AuthUser
		)

		session := sessions.Default(ctx)

		// [zipizap123 note]:
		//	  It took some time to understand the following code, so I've added some
		//	  clarifying notes. Hope they are usefull for other persons ;)
		//
		// If session (cookie) has key "ginoauthazure" with an authUser instance, then the user is already logged-in,
		// so lets propagate the authUser, into ctx-"user" for it to be available for middlewares/handlerfuncs remaining
		// and return
		ginoauthazure := session.Get("ginoauthazure")
		if authUser, ok = ginoauthazure.(AuthUser); ok {
			ctx.Set("user", authUser)
			ctx.Next()
			return
		}

		// If session (cookie) does not have key "ginoauthazure" with an authUser instance,
		// then the user is not yet logged-in.
		// This request received might be:
		//   a) a non-authenticated request, which then deserves to be replied with a "http-401 unauthorized"
		//   b) the oauth2-callback-with-authorization-code that is comming into the redirectURL. (*1)
		//		In this case:
		//      b.1) verify "state"
		//		b.2) exchange authorization-code => access_token,
		//		b.3) define authUser, by using access_token
		//		b.4) define ctx-"user" = authUser, for it to be available for middlewares/handlerfuncs remaining
		// 		b.5) define session-"ginoauthazure" = authUser, so future requests with this session (cookie) are
		//			 treated as logged-in
		//
		// NOTE *1: the redirectUrl can be any url within private, where private is
		// 			private := router.Group("/auth")
		// 			private.Use(azure.Auth())
		// 	So the url http(s)://zzzzz/auth/ would be valid
		// ----------------------------

		// a) + b.1)
		retrievedState := session.Get("state")
		if retrievedState != ctx.Query("state") {
			ctx.AbortWithError(http.StatusUnauthorized, fmt.Errorf("Invalid session state: %s", retrievedState))
			return
		}

		// b,2)
		// TODO: oauth2.NoContext -> context.Context from stdlib
		tok, err := conf.Exchange(oauth2.NoContext, ctx.Query("code"))
		if err != nil {
			ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("Failed to do exchange: %v", err))
			return
		}

		// b.3)
		// Fill authUser
		// Initial approach: pick-up the authUser info from the claims present in access_token
		// A more powerfull approach, would be to use this access_token to make a call to the /me endpoint
		// and get back lots more information from the user (hopefully even the groups it belongs to)
		var claims map[string]interface{} // generic map to store parsed claims
		// decode JWT access_token without verifying the signature
		access_token := tok.AccessToken
		//fmt.Println("debug access_token: ", access_token)
		jwt, _ := jwt.ParseSigned(access_token)
		_ = jwt.UnsafeClaimsWithoutVerification(&claims)
		// claims now filled and ready to be read

		groups, err := getGroupsOfThisUser(access_token)
		if err != nil {
			ctx.AbortWithError(http.StatusBadRequest, fmt.Errorf("Failed to read user groups: %v", err))
			return
		}

		authUser = AuthUser{
			Login:   claims["unique_name"].(string),
			Name:    claims["name"].(string),
			Email:   claims["unique_name"].(string),
			Company: "",
			URL:     "",
			Groups:  groups,
		}

		// b.4)
		// save userinfo, which could be used in Handlers
		ctx.Set("user", authUser)

		// b.5)
		// populate cookie
		session.Set("ginoauthazure", authUser)
		if err := session.Save(); err != nil {
			glog.Errorf("Failed to save session: %v", err)
		}
	}
}

// This function uses the access_token to make a REST-API call in to msgraph and get list of groups to which this user belongs
//
// The access_token should have been created including the required scope `Directory.Read.All` to be able to read the group-names ([1])
//
//
// [1] https://docs.microsoft.com/en-us/graph/api/group-list-transitivememberof?view=graph-rest-1.0&tabs=http
func getGroupsOfThisUser(access_token string) (groupNames []string, err error) {
	url := "https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.group"
	method := "GET"

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return []string{}, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+access_token)

	res, err := client.Do(req)
	if err != nil {
		return []string{}, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return []string{}, err
	}

	var holder interface{}
	err = json.Unmarshal([]byte(string(body)), &holder)
	if err != nil {
		return []string{}, err
	}
	jmespath_query := `value[].displayName`
	jmespath_result, err := jmespath.Search(jmespath_query, holder)
	if err != nil {
		return []string{}, err
	}
	jmespath_result = jmespath_result.([]interface{})
	for _, v := range jmespath_result.([]interface{}) {
		groupNames = append(groupNames, v.(string))
	}
	return groupNames, nil

	/*
		NOTE: this would be the http-response-json if the required scope "Directory.Read.All" was not included in the access_token - notice that displayName are all empty,
		and we only obtain the "id"
		{
		    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#groups",
		    "value": [
		        {
		            "id": "ec230f18-6733-431b-95af-438e34350a6b",
		            "deletedDateTime": null,
		            "classification": null,
		            "createdDateTime": null,
		            "creationOptions": [],
		            "description": null,
		            "displayName": null,
		            "expirationDateTime": null,
		            "groupTypes": [],
		            "isAssignableToRole": null,
		            "mail": null,
		            "mailEnabled": null,
		            "mailNickname": null,
		            "membershipRule": null,
		            "membershipRuleProcessingState": null,
		            "onPremisesDomainName": null,
		            "onPremisesLastSyncDateTime": null,
		            "onPremisesNetBiosName": null,
		            "onPremisesSamAccountName": null,
		            "onPremisesSecurityIdentifier": null,
		            "onPremisesSyncEnabled": null,
		            "preferredDataLocatio     returnnull,
		            "proxyAddresses": [],
		            "renewedDateTime": null,
		            "resourceBehaviorOptions": [],
		            "resourceProvisioningOptions": [],
		            "securityEnabled": null,
		            "securityIdentifier": null,
		            "theme": null,
		            "visibility": null,
		            "onPremisesProvisioningErrors": []
		        },
		        {
		            "id": "e607a5e5-31d0-4988-af64-44496cce64f8",
		            "deletedDateTime": null,
		            "classification": null,
		            "createdDateTime": null,
		            "creationOptions": [],
		            "description": null,
		            "displayName": null,
		            "expirationDateTime": null,
		            "groupTypes": [],
		            "isAssignableToRole": null,
		            "mail": null,
		            "mailEnabled": null,
		            "mailNickname": null,
		            "membershipRule": null,
		            "membershipRuleProcessingState": null,
		            "onPremisesDomainName": null,
		            "onPremisesLastSyncDateTime": null,
		            "onPremisesNetBiosName": null,
		            "onPremisesSamAccountName": null,
		            "onPremisesSecurityIdentifier": null,
		            "onPremisesSyncEnabled": null,
		            "preferredDataLocation": null,
		            "preferredLanguage": null,
		            "proxyAddresses": [],
		            "renewedDateTime": null,
		            "resourceBehaviorOptions": [],
		            "resourceProvisioningOptions": [],
		            "securityEnabled": null,
		            "securityIdentifier": null,
		            "theme": null,
		            "visibility": null,
		            "onPremisesProvisioningErrors": []
		        }
		    ]
		}
	*/
}
