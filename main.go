package main

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"github.com/charmbracelet/log"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Config struct {
	Port  string `json:"port"`
	Users []User `json:"users"`
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	log.Info("New connection", "from", getClientIP(r))

	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer func(destination io.WriteCloser) {
		err := destination.Close()
		if err != nil {

		}
	}(destination)
	defer func(source io.ReadCloser) {
		err := source.Close()
		if err != nil {

		}
	}(source)
	_, err := io.Copy(destination, source)
	if err != nil {
		return
	}
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		return
	}

	logRequest(req)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func basicAuth(users []User, realm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Proxy-Authorization")
			if auth == "" {
				w.Header().Set("Proxy-Authenticate", `Basic realm="`+realm+`"`)
				http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
				return
			}

			authParts := strings.SplitN(auth, " ", 2)
			if len(authParts) != 2 || authParts[0] != "Basic" {
				http.Error(w, "Invalid authentication format", http.StatusBadRequest)
				return
			}

			payload, _ := base64.StdEncoding.DecodeString(authParts[1])
			pair := strings.SplitN(string(payload), ":", 2)
			if len(pair) != 2 {
				http.Error(w, "Invalid authentication format", http.StatusBadRequest)
				return
			}

			authenticated := false
			for _, user := range users {
				if subtle.ConstantTimeCompare([]byte(pair[0]), []byte(user.Username)) == 1 &&
					subtle.ConstantTimeCompare([]byte(pair[1]), []byte(user.Password)) == 1 {
					authenticated = true
					break
				}
			}

			if !authenticated {
				w.Header().Set("Proxy-Authenticate", `Basic realm="`+realm+`"`)
				http.Error(w, "Invalid username or password", http.StatusProxyAuthRequired)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func loadConfig(filename string) (Config, error) {
	var config Config
	file, err := os.Open(filename)
	if err != nil {
		return config, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return config, err
	}

	return config, nil
}

func getClientIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		return strings.Split(ip, ",")[0]
	}

	ip = r.Header.Get("X-Real-IP")
	if ip != "" {
		return ip
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func createDefaultConfigIfNotExist(filename string) error {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		defaultConfig := Config{
			Port: "8080",
			Users: []User{
				{
					Username: "username",
					Password: "password",
				},
			},
		}

		file, err := os.Create(filename)
		if err != nil {
			return err
		}
		defer func(file *os.File) {
			err := file.Close()
			if err != nil {

			}
		}(file)

		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "    ")
		if err := encoder.Encode(defaultConfig); err != nil {
			return err
		}

		log.Info("New configuration file created with default values", "filename", filename)
	}

	return nil
}

func logRequest(r *http.Request) {
	log.Info("New requests", "from", getClientIP(r), "to", r.URL.String(), "method", r.Method)
}

func main() {
	configFile := "config.json"

	if err := createDefaultConfigIfNotExist(configFile); err != nil {
		log.Fatal("Error when creating configuration file", "err", err)
	}

	config, err := loadConfig(configFile)
	if err != nil {
		log.Fatal("Error while loading configuration", "err", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			handleTunneling(w, r)
		} else {
			handleHTTP(w, r)
		}
	})

	authenticatedHandler := basicAuth(config.Users, "proxy")(handler)

	server := &http.Server{
		Addr:    ":" + config.Port,
		Handler: authenticatedHandler,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	log.Info("Start listening for requests", "port", config.Port)
	log.Fatal(server.ListenAndServe())
}
