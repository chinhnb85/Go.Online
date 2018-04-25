package main

import (
	"io/ioutil"
	"log"
	"strings"
	"net/http"
	"encoding/json"
	"fmt"
	"time"
	"crypto/rsa"

	"github.com/codegangsta/negroni"
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	//"./rsakey"
	//"./login"
)


//RSA KEYS AND INITIALISATION


const (
	privKeyPath = "secret/app.rsa"
	pubKeyPath = "secret/app.rsa.pub"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

func initKeys(){

	signKeyByte, err := ioutil.ReadFile(privKeyPath)
	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signKeyByte)
	if err != nil {
		log.Fatal("Error reading private key")
		return
	}

	verifyKeyByte, err := ioutil.ReadFile(pubKeyPath)
	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyKeyByte)
	if err != nil {
		log.Fatal("Error reading public key")
		return
	}
}



//STRUCT DEFINITIONS


type userCredentials struct {
	Username	string  `json:"username"`
	Password	string	`json:"password"`
}

type user struct {
	ID			int 	`json:"id"`
	Name		string  `json:"name"`
	Username	string  `json:"username"`
	Password	string	`json:"password"`
}

type response struct {
	Data	string	`json:"data"`
}

type token struct {
	Token 	string    `json:"token"`
	Exp 	int64    `json:"exp"`
}



//SERVER ENTRY POINT


func startServer(){

	//PUBLIC ENDPOINTS
	http.HandleFunc("/login", loginHandler)

	//PROTECTED ENDPOINTS
	http.Handle("/resource/", negroni.New(
		negroni.HandlerFunc(validateTokenMiddleware),
		negroni.Wrap(http.HandlerFunc(protectedHandler)),
	))


	

	log.Println("Now listening...")
	http.ListenAndServe(":8000", nil)
}

func main() {

	//rsakey.GenKeyRSA()
	
	//login.IsValidUser()

	initKeys()
	startServer()
}


//////////////////////////////////////////


/////////////ENDPOINT HANDLERS////////////


/////////////////////////////////////////


func protectedHandler(w http.ResponseWriter, r *http.Request){

	response := response{"Gained access to protected resource"}
	jsonResponse(response, w)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	var user userCredentials

	//decode request into UserCredentials struct
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "Error in request")
		return
	}

	fmt.Println(user.Username, user.Password)

	//validate user credentials
	if strings.ToLower(user.Username) != "chinhnb" {
		if user.Password != "12" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Println("Error logging in")
			fmt.Fprint(w, "Invalid credentials")
			return
		}
	}

	//create a rsa 256 signer
	signer := jwt.New(jwt.GetSigningMethod("RS256"))

	//set claims
	exp:=time.Now().Add(time.Minute * 2).Unix()
	claims := make(jwt.MapClaims)
	claims["iss"] = "admin"
	claims["exp"] = exp
	claims["CustomUserInfo"] = struct {
		Name	string
		Role	string
	}{user.Username, "Member"}
	signer.Claims = claims

	tokenString, err := signer.SignedString(signKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Error while signing the token")
		log.Printf("Error signing token: %v\n", err)
	}

	//create a token instance using the token string
	response := token{tokenString,exp}
	jsonResponse(response, w)
}



//AUTH TOKEN VALIDATION

func validateTokenMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	//validate token
	token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor,
		func(token *jwt.Token) (interface{}, error) {
			return verifyKey, nil
	})

	if err == nil {

		if token.Valid{
			next(w, r)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Token is not valid")
		}
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Unauthorised access to this resource")
	}

}



//HELPER FUNCTIONS


func jsonResponse(response interface{}, w http.ResponseWriter) {

	json, err :=  json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}
