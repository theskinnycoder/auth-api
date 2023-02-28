package main

import (
	"github.com/theskinnycoder/auth-api/lib"
	"github.com/theskinnycoder/auth-api/routes"
)

func main() {
	lib.InitDB()
	routes.HandleFuncs()
}
