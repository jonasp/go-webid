# WebID for GO

A basic library to validate a WebID.
The only function so far is `webid.Validate(tls *tls.ConnectionState)` which should be called in the handler function. It returns a (\*id, err) with the subjectAltName in `id.Name` and result of the validation in `id.Valid`.

## Example

```go
package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"webid"
)

func handler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")

	id, err := webid.Validate(req.TLS)
	if err != nil {
		w.Write([]byte(fmt.Sprintln(err)))
	} else {
		w.Write([]byte(fmt.Sprintln(id.Name, "is valid?", id.Valid)))
	}
}

func main() {
	http.HandleFunc("/", handler)
	log.Printf("About to listen on 10443. Go to https://127.0.0.1:10443/")
	server := &http.Server{Addr: ":10443"}
	server.TLSConfig = &tls.Config{ClientAuth: tls.RequestClientCert}
	err := server.ListenAndServeTLS("https/keys/cert.pem", "https/keys/key.pem")
	if err != nil {
		log.Fatal(err)
	}
}
```
