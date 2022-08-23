package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
)

type GM struct {
	router     *mux.Router
	supervisor *Supervisor
}

func NewGM(supervisor *Supervisor) *GM {
	return &GM{router: mux.NewRouter(), supervisor: supervisor}
}

// CreateHandler creates http handlers to process the program stdout and stderr through http interface
func (gm *GM) CreateHandler() http.Handler {
	gm.router.HandleFunc("/clearCache", gm.clearCache).Methods("POST", "GET")

	return gm.router
}

func (gm *GM) clearCache(writer http.ResponseWriter, request *http.Request) {
	fmt.Println(request.PostForm)

	writer.WriteHeader(200)
}
