package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Kaese72/riskie-lib/logging"
	"github.com/georgysavva/scany/v2/sqlscan"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"
	"go.elastic.co/apm/module/apmsql"
	_ "go.elastic.co/apm/module/apmsql/mysql"
)

type Organization struct {
	ID int `json:"id"`
}

type contextKey string

const (
	userIDKey         contextKey = "userID"
	organizationIDKey contextKey = "organizationID"
)

func (app application) authenticateToken(tokenString string) (int, int, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(app.jwtSecret), nil
	})

	if err != nil {
		return 0, 0, errors.New("error token")
	}

	if !token.Valid {
		return 0, 0, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, 0, errors.New("invalid claims")
	}

	userID, ok := claims[string(userIDKey)].(float64)
	if !ok {
		return 0, 0, errors.New("invalid user id")
	}
	organizationID, ok := claims[string(organizationIDKey)].(float64)
	if !ok {
		return 0, 0, errors.New("invalid organization id")
	}
	return int(userID), int(organizationID), nil
}

func (app application) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
		userId, organizationId, err := app.authenticateToken(tokenString)
		if err != nil {
			// FIXME should to be able to differentiate between invalid token and expired token
			logging.Error(r.Context(), err.Error())
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), userIDKey, userId)
		ctx = context.WithValue(ctx, organizationIDKey, organizationId)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type User struct {
	ID           int    `json:"id"`
	Organization int    `json:"organization"`
	Username     string `json:"username"`
}

// UserSecret is a User but with secret fields
type UserSecret struct {
	Password string `json:"password"`
	User
}

type application struct {
	db        *sql.DB
	jwtSecret string
}

func (app application) attemptLogin(ctx context.Context, username string, password string) (User, error) {
	var user User
	err := app.db.QueryRowContext(ctx, "SELECT id, organization FROM users WHERE username = ? AND password = ?", username, password).Scan(&user.ID, &user.Organization)
	return user, err
}

// func (app application)updatePassword(ctx context.Context, id int, password string) (User, error) {
// 	var user User
// 	result, err := app.db.ExecContext(ctx, "UPDATE users SET password = ? WHERE id = ?", password, id)
// 	if err != nil {
// 		return user, err
// 	}
// 	affected, err := result.RowsAffected()
// 	if err != nil {
// 		return user, err
// 	}
// 	if affected == 0 {
// 		return user, fmt.Errorf("user not found")
// 	}
// 	return user, err
// }

func (app application) createToken(user User) (string, error) {
	// Create a new JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID":         user.ID,
		"organizationID": user.Organization,
		"exp":            time.Now().Add(time.Hour).Unix(),
	})

	// Sign the token with a secret key
	tokenString, err := token.SignedString([]byte(app.jwtSecret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func DBReadUsers(ctx context.Context, db *sql.DB, organization int) ([]User, error) {
	users := []User{}
	err := sqlscan.Select(ctx, db, &users, `SELECT id,organization,username FROM users where organization = ?`, organization)
	return users, err
}

func DBReadUser(ctx context.Context, db *sql.DB, organization int, id int) (User, error) {
	users := []User{}
	err := sqlscan.Select(ctx, db, &users, `SELECT id,organization,username FROM users WHERE organization = ? AND id = ?`, organization, id)
	if len(users) == 0 {
		return User{}, fmt.Errorf("user not found")
	}
	return users[0], err
}

func DBCreateUser(ctx context.Context, db *sql.DB, user UserSecret) (User, error) {
	resUsers := []User{}
	result, err := db.QueryContext(ctx, `INSERT INTO users (organization, username, password) VALUES (?, ?, ?) RETURNING id,organization,username`, user.Organization, user.Username, user.Password)
	if err != nil {
		return User{}, err
	}
	err = sqlscan.ScanAll(&resUsers, result)
	if err != nil {
		return User{}, err
	}
	if len(resUsers) == 0 {
		return User{}, fmt.Errorf("user not created")
	}
	return resUsers[0], err
}

func DBUpdateUser(ctx context.Context, db *sql.DB, user User, userId int, organizationId int) (User, error) {
	resUsers := []User{}
	sqlString := ""
	arguments := []interface{}{}
	for _, u := range resUsers {
		if u.Organization != user.Organization {
			sqlString += "organization = ?,"
			arguments = append(arguments, user.Organization)
		}
		if u.Username != user.Username {
			sqlString += "username = ?,"
			arguments = append(arguments, user.Username)
		}
	}
	// These are used to prevent updating of other organizations users
	sqlString += " WHERE id = ? AND organization = ?"
	arguments = append(arguments, userId)
	arguments = append(arguments, organizationId)
	result, err := db.QueryContext(ctx, fmt.Sprintf(`UPDATE users SET %s RETURNING id,organization,username`, sqlString), arguments...)
	if err != nil {
		return User{}, err
	}
	err = sqlscan.ScanAll(&resUsers, result)
	if err != nil {
		return User{}, err
	}
	if len(resUsers) == 0 {
		return User{}, fmt.Errorf("user not updated")
	}
	return resUsers[0], err
}

func DBRegisterOrganization(ctx context.Context, db *sql.DB, username string, password string) (Organization, User, error) {
	resOrgs := []Organization{}
	resUsers := []User{}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Organization{}, User{}, err
	}
	result, err := tx.QueryContext(ctx, `INSERT INTO organizations () VALUES () RETURNING id`)
	if err != nil {
		return Organization{}, User{}, err
	}
	err = sqlscan.ScanAll(&resOrgs, result)
	if err != nil {
		return Organization{}, User{}, err
	}
	if len(resOrgs) == 0 {
		return Organization{}, User{}, fmt.Errorf("organization not created")
	}
	result, err = tx.QueryContext(ctx, `INSERT INTO users (organization, username, password) VALUES (?, ?, ?) RETURNING id, organization,username`, resOrgs[0].ID, username, password)
	if err != nil {
		return Organization{}, User{}, err
	}
	err = sqlscan.ScanAll(&resUsers, result)
	if err != nil {
		return Organization{}, User{}, err
	}
	if len(resUsers) == 0 {
		return Organization{}, User{}, fmt.Errorf("user not created")
	}
	err = tx.Commit()
	if err != nil {
		return Organization{}, User{}, err
	}
	return resOrgs[0], resUsers[0], err
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
	cookie, err := r.Cookie("organizationLoginToken")
	var loggedInUser User
	if err == nil {
		userId, organizationId, err := app.authenticateToken(cookie.Value)
		if err != nil {
			logging.Error(r.Context(), err.Error())
			// Proceeding anyway with other authentication methods
		} else {
			// Token is valid, proceed with the user
			loggedInUser, err = DBReadUser(r.Context(), app.db, organizationId, userId)
			if err != nil {
				// We pretty much ignore this issue and proceed with the other authentication methods
				logging.Error(r.Context(), err.Error())
			}
		}
	}

	if loggedInUser.ID == 0 {
		// Logged in is not set, thus we need to try to authenticate
		ctx := r.Context()
		input := struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}{}
		err = json.NewDecoder(r.Body).Decode(&input)
		if err != nil {
			APIError(w, "Failed to parse JSON body", http.StatusBadRequest)
			return
		}
		if input.Username == "" || input.Password == "" {
			APIError(w, "Username or password missing in webform", http.StatusBadRequest)
			return
		}

		loggedInUser, err = app.attemptLogin(ctx, input.Username, input.Password)
		if err != nil {
			APIError(w, "Failed to login", http.StatusUnauthorized)
			return
		}
	}

	// Create JWT token
	token, err := app.createToken(loggedInUser)
	if err != nil {
		logging.Error(r.Context(), err.Error())
		APIError(w, "Failed to create JWT token", http.StatusInternalServerError)
		return
	}

	// Example response
	response := struct {
		Message string `json:"message"`
		Token   string `json:"token"`
	}{
		Message: "Login successful",
		Token:   token,
	}

	jsonResponse, err := json.MarshalIndent(response, "", "   ")
	if err != nil {
		logging.Error(r.Context(), err.Error())
		APIError(w, "Failed to marshal JSON response", http.StatusInternalServerError)
		return
	}
	cookie = &http.Cookie{
		Name:     "organizationLoginToken",
		Value:    token,
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

func (app application) readUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]
	if userID == "" {
		APIError(w, "userID missing", http.StatusBadRequest)
		return
	}
	userIdInt, err := strconv.Atoi(userID)
	if err != nil {
		APIError(w, "userID is not a number", http.StatusBadRequest)
		return
	}
	organizationID := r.Context().Value(organizationIDKey).(float64)
	user, err := DBReadUser(r.Context(), app.db, int(organizationID), userIdInt)
	if err != nil {
		logging.Error(r.Context(), err.Error())
		APIError(w, "Failed to read user", http.StatusInternalServerError)
		return
	}
	jsonResponse, err := json.MarshalIndent(user, "", "   ")
	if err != nil {
		logging.Error(r.Context(), err.Error())
		APIError(w, "Failed to marshal JSON response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

func (app application) readUsers(w http.ResponseWriter, r *http.Request) {
	organizationID := r.Context().Value(organizationIDKey).(float64)
	users, err := DBReadUsers(r.Context(), app.db, int(organizationID))
	if err != nil {
		logging.Error(r.Context(), err.Error())
		APIError(w, "Failed to read users", http.StatusInternalServerError)
		return
	}
	jsonResponse, err := json.MarshalIndent(users, "", "   ")
	if err != nil {
		logging.Error(r.Context(), err.Error())
		APIError(w, "Failed to marshal JSON response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

func (app application) registerOrganization(w http.ResponseWriter, r *http.Request) {
	input := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{}
	err := json.NewDecoder(r.Body).Decode(&input)
	if err != nil {
		logging.Error(r.Context(), err.Error())
		APIError(w, "Failed to parse JSON body", http.StatusBadRequest)
		return
	}
	organization, user, err := DBRegisterOrganization(r.Context(), app.db, input.Username, input.Password)
	if err != nil {
		logging.Error(r.Context(), err.Error())
		APIError(w, "Failed to register organization", http.StatusInternalServerError)
		return
	}
	response := struct {
		Organization Organization `json:"organization"`
		User         User         `json:"user"`
	}{Organization: organization, User: user}
	jsonResponse, err := json.MarshalIndent(response, "", "   ")
	if err != nil {
		logging.Error(r.Context(), err.Error())
		APIError(w, "Failed to marshal JSON response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

func (app application) createUser(w http.ResponseWriter, r *http.Request) {
	organizationID := r.Context().Value(organizationIDKey).(float64)
	inputUser := UserSecret{}
	err := json.NewDecoder(r.Body).Decode(&inputUser)
	if err != nil {
		logging.Error(r.Context(), err.Error())
		APIError(w, "Failed to parse JSON body", http.StatusBadRequest)
		return
	}
	// Always set the organization to the current user's organization
	inputUser.Organization = int(organizationID)
	user, err := DBCreateUser(r.Context(), app.db, inputUser)
	if err != nil {
		logging.Error(r.Context(), err.Error())
		APIError(w, "Failed to create user", http.StatusInternalServerError)
		return
	}
	jsonResponse, err := json.MarshalIndent(user, "", "   ")
	if err != nil {
		logging.Error(r.Context(), err.Error())
		APIError(w, "Failed to marshal JSON response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
}

func (app application) updateUser(w http.ResponseWriter, r *http.Request) {
	organizationID := r.Context().Value(organizationIDKey).(float64)
	vars := mux.Vars(r)
	userID := vars["id"]
	if userID == "" {
		APIError(w, "userID missing", http.StatusBadRequest)
		return
	}
	userIdInt, err := strconv.Atoi(userID)
	if err != nil {
		APIError(w, "userID is not a number", http.StatusBadRequest)
		return
	}
	inputUser := User{}
	err = json.NewDecoder(r.Body).Decode(&inputUser)
	if err != nil {
		logging.Error(r.Context(), err.Error())
		APIError(w, "Failed to parse JSON body", http.StatusBadRequest)
		return
	}
	// Always set the organization to the current user's organization
	inputUser.Organization = int(organizationID)
	user, err := DBUpdateUser(r.Context(), app.db, inputUser, userIdInt, int(organizationID))
	if err != nil {
		logging.Error(r.Context(), err.Error())
		APIError(w, "Failed to update user", http.StatusInternalServerError)
		return
	}
	jsonResponse, err := json.MarshalIndent(user, "", "   ")
	if err != nil {
		logging.Error(r.Context(), err.Error())
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
		logging.Fatal(context.Background(), err.Error())
	}

	if Loaded.Database.Host == "" {
		logging.Fatal(context.Background(), "Database host not set")
	}

	if Loaded.Database.Password == "" {
		logging.Fatal(context.Background(), "Database password not set")
	}

	if Loaded.Database.User == "" {
		logging.Fatal(context.Background(), "Database user not set")
	}

	if Loaded.JWT.Secret == "" {
		logging.Fatal(context.Background(), "JWT secret key not set")
	}
}

func main() {
	db, err := apmsql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", Loaded.Database.User, Loaded.Database.Password, Loaded.Database.Host, Loaded.Database.Port, Loaded.Database.Database))
	if err != nil {
		logging.Fatal(context.Background(), err.Error())
	}
	defer db.Close()

	app := application{db: db, jwtSecret: Loaded.JWT.Secret}
	// organization-registry is the prefix for all routes for this API
	router := mux.NewRouter().PathPrefix("/organization-registry").Subrouter()
	// Unauthenticated routes
	unauthenticatedRouter := router.PathPrefix("").Subrouter()
	unauthenticatedRouter.HandleFunc("/auth/login", app.login).Methods("POST")
	unauthenticatedRouter.HandleFunc("/organizations/register", app.registerOrganization).Methods("POST")

	// Authenticated required
	authenticatedRouter := router.NewRoute().Subrouter()
	authenticatedRouter.Use(app.authMiddleware)
	// authenticatedRouter.HandleFunc("/users/changemypw", app.changeMyPassword).Methods("POST")
	authenticatedRouter.HandleFunc("/users/{id:[0-9]+}", app.readUser).Methods("GET")
	authenticatedRouter.HandleFunc("/users", app.readUsers).Methods("GET")
	authenticatedRouter.HandleFunc("/users", app.createUser).Methods("POST")
	authenticatedRouter.HandleFunc("/user/{id:[0-9]+}", app.updateUser).Methods("POST")

	logging.Fatal(context.Background(), http.ListenAndServe(fmt.Sprintf("%s:%d", Loaded.Listen.Host, Loaded.Listen.Port), router).Error())
}
