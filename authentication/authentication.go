package authentication

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Kaese72/riskie-lib/apierror"
	"github.com/dgrijalva/jwt-go"
)

type contextKey string

const (
	UserIDKey         contextKey = "userID"
	OrganizationIDKey contextKey = "organizationID"
)

func DefaultJWTAuthentication(secret string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString := r.Header.Get("Authorization")
			if tokenString == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
			userID, organizationID, err := AuthenticateToken(secret, tokenString)
			if err != nil {
				apierror.TerminalHTTPError(r.Context(), w, err)
				return
			}

			ctx := context.WithValue(r.Context(), UserIDKey, userID)
			ctx = context.WithValue(ctx, OrganizationIDKey, organizationID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func AuthenticateToken(jwtSecret string, jwtToken string) (float64, float64, error) {
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(jwtSecret), nil
	})
	if err != nil {
		return 0, 0, apierror.APIError{Code: http.StatusUnauthorized, WrappedError: fmt.Errorf("error parsing token: %s", err.Error())}
	}

	if !token.Valid {
		return 0, 0, apierror.APIError{Code: http.StatusUnauthorized, WrappedError: errors.New("invalid token")}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, 0, apierror.APIError{Code: http.StatusUnauthorized, WrappedError: errors.New("could not read claims")}
	}
	userID, ok := claims[string(UserIDKey)].(float64)
	if !ok {
		return 0, 0, apierror.APIError{Code: http.StatusUnauthorized, WrappedError: errors.New("could not read userId claim")}

	}
	organizationID, ok := claims[string(OrganizationIDKey)].(float64)
	if !ok {
		return 0, 0, apierror.APIError{Code: http.StatusUnauthorized, WrappedError: errors.New("could not read organizationId claim")}
	}
	return userID, organizationID, nil
}
