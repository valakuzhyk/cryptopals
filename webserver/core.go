package webserver

import (
	"log"
	"net/http"
)

var key string = "YELLOWSUBMARINE"

// StartHTTPServer can be used to start and end a webserver
func StartHTTPServer() *http.Server {
	key = "YELLOWSUBMARINE"
	srv := &http.Server{Addr: ":8080"}

	http.HandleFunc("/challenge31", hmacFileValidator)
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			// cannot panic, because this probably is an intentional close
			log.Printf("Httpserver: ListenAndServe() error: %s", err)
		}
	}()

	// returning reference so caller can call Shutdown()
	return srv
}
