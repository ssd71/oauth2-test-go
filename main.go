package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

const JWT_SIGNING_KEY = "haule haule"

var clients = map[string]string{
	"client_id_123": "client_secret_123",
}

var redirect_uri = map[string]string{
	"client_id_123": "http://localhost:3000",
}

type CodeResponse struct {
}

type JwtClaims struct {
	jwt.RegisteredClaims
	Given_name  string `json:"given_name,omitempty"`
	Family_name string `json:"family_name,omitempty"`
}

type UserInfo struct {
	Given_name      string
	Family_name     string
	Hashed_password []byte
	Email_verified  bool
}

var hashed_pass, _ = bcrypt.GenerateFromPassword([]byte("Password"), 10)

var users = map[string]UserInfo{
	"abc@email.com": {
		Given_name:      "ABC",
		Family_name:     "DEF",
		Hashed_password: hashed_pass,
		Email_verified:  true,
	},
}

type TokenData struct {
	user_id string
	scopes  []string
}

type AuthRequestData struct {
	token_data TokenData
	client_id  string
}

var auth_code_requests = make(map[string]AuthRequestData)

var tokens = make(map[string]TokenData)

var supported_scopes = []string{"openid", "profile"}

// TemplateRenderer is a custom html/template renderer for Echo framework
type TemplateRenderer struct {
	templates *template.Template
}

// Render renders a template document
func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {

	// Add global methods if data is a map
	if viewContext, isMap := data.(map[string]interface{}); isMap {
		viewContext["reverse"] = c.Echo().Reverse
	}

	return t.templates.ExecuteTemplate(w, name, data)
}

func main() {
	jwtPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return
	}

	e := echo.New()
	e.Use(session.Middleware(sessions.NewCookieStore([]byte("secret"))))
	renderer := &TemplateRenderer{
		templates: template.Must(template.ParseGlob("templates/*.html")),
	}
	e.Renderer = renderer

	// Named route "foobar"
	e.GET("/", func(c echo.Context) error {
		params := c.QueryParams()

		// check scopes
		_request_scopes := params.Get("scope")
		request_scopes := strings.Split(_request_scopes, " ")
		for _, rs := range request_scopes {
			supported := false
			for _, ss := range supported_scopes {
				if rs == ss {
					supported = true
				}
			}
			if !supported {
				return echo.NewHTTPError(http.StatusBadRequest, "Unsupported scope")
			}
		}

		// check response type
		response_type := params.Get("response_type")
		if response_type != "code" {
			return echo.NewHTTPError(http.StatusBadRequest, "Unsupported reponse type")
		}

		_, client_exists := clients[params.Get("client_id")]

		// check client id
		if !client_exists {
			return echo.NewHTTPError(http.StatusBadRequest, "Client unknown")
		}

		// check redirect uri
		if params.Get("redirect_uri") != redirect_uri[params.Get("client_id")] {
			return echo.NewHTTPError(http.StatusBadRequest, "Bad Redirect URI")
		}

		return c.Render(http.StatusOK, "index.html", nil)

	})

	e.POST("/", func(c echo.Context) error {
		data, _ := c.FormParams()

		user_data, exists := users[data.Get("username")]

		if !exists {
			return echo.NewHTTPError(http.StatusUnauthorized)
		}

		err := bcrypt.CompareHashAndPassword(user_data.Hashed_password, []byte(data.Get("password")))

		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized)
		}

		// User exists and is authenticated
		// Generate auth code, associate to client and user, and send in redirect
		_auth_code := make([]byte, 32)
		_, err = rand.Read(_auth_code)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError)
		}
		auth_code := hex.EncodeToString(_auth_code)
		auth_code_requests[string(auth_code)] = AuthRequestData{
			client_id: c.QueryParam("client_id"),
			token_data: TokenData{
				user_id: c.FormValue("username"),
				scopes:  strings.Fields(c.QueryParam("scope")),
			},
		}

		return c.Redirect(http.StatusTemporaryRedirect, "http://localhost:3000"+"?code="+string(auth_code)+"&state="+c.QueryParam("state"))
	})

	type TokenRequestData struct {
		Grant_type    string `form:"grant_type"`
		Code          string `form:"code"`
		Client_id     string `form:"client_id"`
		Client_secret string `form:"client_secret"`
	}

	e.POST("/token", func(c echo.Context) error {
		fmt.Print(c.FormParams())
		var data = TokenRequestData{}
		err := c.Bind(&data)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest)
		}

		fmt.Printf("%v", data)

		if data.Grant_type != "code" {
			return echo.NewHTTPError(http.StatusForbidden)
		}

		fmt.Print(data)
		// check client_id and client_secret
		if secret, exists := clients[data.Client_id]; !exists || secret != data.Client_secret {

			return echo.NewHTTPError(http.StatusUnauthorized)
		}

		fmt.Print(data)
		// check if code is valid and client_id corresponds to authorization code
		code_data, exists := auth_code_requests[data.Code]
		if !exists || code_data.client_id != data.Client_id {
			return echo.NewHTTPError(http.StatusForbidden)
		}

		// issue access token and revoke the authorization code
		fmt.Print(data)
		_access_token := make([]byte, 64)
		_, err = rand.Read(_access_token)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError)
		}
		access_token := hex.EncodeToString(_access_token)

		tokens[access_token] = TokenData{
			user_id: code_data.token_data.user_id,
			scopes:  code_data.token_data.scopes,
		}

		id_token_claims := JwtClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:   "http://localhost:8000",
				Subject:  code_data.token_data.user_id,
				Audience: jwt.ClaimStrings{code_data.client_id},
			},
		}

		for _, scope := range code_data.token_data.scopes {
			if scope == "profile" {
				user_data := users[id_token_claims.Subject]
				id_token_claims.Given_name, id_token_claims.Family_name = user_data.Given_name, user_data.Family_name
			}
		}

		id_token_jwt := jwt.NewWithClaims(jwt.SigningMethodRS512, id_token_claims)
		signed_jwt, err := id_token_jwt.SignedString(jwtPrivateKey)

		fmt.Print(data)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError)
		}

		return c.JSON(http.StatusOK, map[string]string{
			"access_token": access_token,
			"id_token":     signed_jwt,
		})
	})

	e.Logger.Fatal(e.Start(":8000"))
}
