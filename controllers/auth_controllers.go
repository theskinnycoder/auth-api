package controllers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/theskinnycoder/auth-api/lib"
	"github.com/theskinnycoder/auth-api/models"
	"golang.org/x/crypto/bcrypt"
)

func Register(w http.ResponseWriter, r *http.Request) {
	var data map[string]string

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Invalid request body",
		})
		return
	}
	hashedPass, _ := bcrypt.GenerateFromPassword([]byte(data["password"]), bcrypt.DefaultCost)
	user := models.User{
		Email:    data["email"],
		Password: string(hashedPass),
	}
	lib.DB.Create(&user)

	accessTokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Issuer:    strconv.Itoa(int(user.ID)),
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	})

	accessToken, _ := accessTokenClaims.SignedString([]byte("secret"))
	refreshToken, _ := accessTokenClaims.SignedString([]byte("secret"))

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Expires:  time.Now().Add(time.Hour * 24 * 7 * 4 * 3),
		HttpOnly: true,
	})

	json.NewEncoder(w).Encode(map[string]string{
		"accessToken": accessToken,
	})
}

func Login(w http.ResponseWriter, r *http.Request) {
	var data map[string]string

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Invalid request body",
		})
		return
	}

	var user models.User
	lib.DB.Where("email = ?", data["email"]).First(&user)
	if user.ID == 0 {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Invalid email or password",
		})
		return
	}

	userEnteredPass, hashedPass := []byte(data["password"]), []byte(user.Password)

	if err := bcrypt.CompareHashAndPassword(hashedPass, userEnteredPass); err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Invalid email or password",
		})
		return
	}

	accessTokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Issuer:    strconv.Itoa(int(user.ID)),
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	})

	accessToken, _ := accessTokenClaims.SignedString([]byte("secret"))
	refreshToken, _ := accessTokenClaims.SignedString([]byte("secret"))

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Expires:  time.Now().Add(time.Hour * 24 * 7 * 4 * 3),
		HttpOnly: true,
	})

	json.NewEncoder(w).Encode(map[string]string{
		"accessToken": accessToken,
	})
}

func Me(w http.ResponseWriter, r *http.Request) {
	accessToken := strings.Split(r.Header.Get("Authorization"), " ")[1]
	if token, err := jwt.ParseWithClaims(accessToken, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	}); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Invalid access token",
		})
		return
	} else {
		claims := token.Claims.(*jwt.StandardClaims)
		var user models.User
		lib.DB.Where("id = ?", claims.Issuer).First(&user)
		json.NewEncoder(w).Encode(map[string]string{
			"email": user.Email,
		})
	}
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.Cookies()[0].Value
	if token, err := jwt.ParseWithClaims(refreshToken, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	}); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Unauthenticated",
		})
		return
	} else {
		accessTokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
			Issuer:    token.Claims.(*jwt.StandardClaims).Issuer,
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
		})

		accessToken, _ := accessTokenClaims.SignedString([]byte("secret"))
		json.NewEncoder(w).Encode(map[string]string{
			"accessToken": accessToken,
		})
	}
}

func Logout(w http.ResponseWriter, _ *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
	})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Logged out successfully",
	})
}
