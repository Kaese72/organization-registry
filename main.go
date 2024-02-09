package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"
)

type Organization struct {
	ID            	int    `json:"id"`
}

type User struct {
	ID            	int    `json:"id"`
	OrganizationID 	int    `json:"organization"`
	Admin		  	bool   `json:"admin"`
}

type UserSecret struct {
	Username	  	string `json:"username"`
	Password	  	string `json:"password"`
	User
}

type application struct {
	db *sql.DB
	jwtSecret string
}

func (app application)attemptLogin(username string, password string) (User, error) {
	var user User
	err := app.db.QueryRow("SELECT id, organization, admin FROM users WHERE username = ? AND password = ?", username, password).Scan(&user.ID, &user.OrganizationID, &user.Admin)
	return user, err
}

func (app application)createToken(user User) (string, error) {

	// Create a new JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID": user.ID,
		"organizationID": user.OrganizationID,
		"admin":  user.Admin,
		"exp":   time.Now().Add(time.Hour).Unix(),
	})

	// Sign the token with a secret key
	tokenString, err := token.SignedString([]byte(app.jwtSecret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func APIError(w http.ResponseWriter, message string, code int) {
	response := struct {
		Message string `json:"message"`
	}{
		Message: message,
	}

	jsonResponse, err := json.MarshalIndent(response, "", "   ")
	if err != nil {
		http.Error(w, "Failed to marshal JSON response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(jsonResponse)
	w.Write([]byte("\n"))
}


func (app application) login(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		APIError(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}

	username := r.Form.Get("username")
	password := r.Form.Get("password")

	if username == "" || password == "" {
		APIError(w, "Username or password missing in webform", http.StatusBadRequest)
		return
	}


	loggedInUser, err := app.attemptLogin(username, password)
	if err != nil {	
		APIError(w, "Failed to login", http.StatusUnauthorized)
		return
	}

	// Create JWT token
	token, err := app.createToken(loggedInUser)
	if err != nil {
		APIError(w, "Failed to create JWT token", http.StatusInternalServerError)
		return
	}

	// Example response
	response := struct {
		Message string `json:"message"`
		Token string `json:"token"`
	}{
		Message: "Login successful",
		Token: token,
	}

	jsonResponse, err := json.MarshalIndent(response, "", "   ")
	if err != nil {
		APIError(w, "Failed to marshal JSON response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

type Config struct {
	Database struct {
		Host     string `mapstructure:"host"`
		Port     int    `mapstructure:"port"`
		User     string `mapstructure:"user"`
		Password string `mapstructure:"password"`
		Database string `mapstructure:"database"`
	} `mapstructure:"database"`
	JWT struct {
		Secret string `mapstructure:"secret"`
	} `mapstructure:"jwt"`
	Listen struct {
		Host string `mapstructure:"host"`
		Port int    `mapstructure:"port"`
	} `mapstructure:"listen"`
}

var Loaded Config

func init() {
	// Load configuration from environment
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.BindEnv("database.host")
	viper.BindEnv("database.port")
	viper.SetDefault("database.port", "3306")
	viper.BindEnv("database.user")
	viper.BindEnv("database.password")
	viper.BindEnv("database.database")
	viper.SetDefault("database.database", "organizationregistry")

	// JWT configuration
	viper.BindEnv("jwt.secret")

	// HTTP listen config
	viper.BindEnv("listen.host")
	viper.SetDefault("listen.host", "0.0.0.0")
	viper.BindEnv("listen.port")
	viper.SetDefault("listen.port", "8080")

	err := viper.Unmarshal(&Loaded)
	if err != nil {
		log.Fatal(err.Error())
	}

	if Loaded.Database.Host == "" {
		log.Fatal("Database host not set")
	}

	if Loaded.Database.Password == "" {
		log.Fatal("Database password not set")
	}

	if Loaded.Database.User == "" {
		log.Fatal("Database user not set")
	}

	if Loaded.JWT.Secret == "" {
		log.Fatal("JWT secret key not set")
	}
}


func main() {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", Loaded.Database.User, Loaded.Database.Password, Loaded.Database.Host, Loaded.Database.Port, Loaded.Database.Database))
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

	
	app := application{db: db, jwtSecret: Loaded.JWT.Secret}
	router := mux.NewRouter()

	router.HandleFunc("/organizations/user/login", app.login).Methods("POST")
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", Loaded.Listen.Host, Loaded.Listen.Port), router))
}

