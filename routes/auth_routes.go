package routes

import (
	"net/http"

	"github.com/theskinnycoder/auth-api/controllers"
)

func HandleFuncs() {
	http.HandleFunc("/register", controllers.Register)
	http.HandleFunc("/login", controllers.Login)
	http.HandleFunc("/me", controllers.Me)
	http.HandleFunc("/logout", controllers.Logout)
	http.ListenAndServe(":8080", nil)
}
