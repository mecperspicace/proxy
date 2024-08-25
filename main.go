package main

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type Config struct {
    Port     string `json:"port"`
    Username string `json:"username"`
    Password string `json:"password"`
    Realm    string `json:"realm"`
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
    // log.Printf("CONNECT request to: %s", r.Host)
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
    go transfer(destConn, clientConn)
    go transfer(clientConn, destConn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
    defer destination.Close()
    defer source.Close()
    io.Copy(destination, source)
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
    resp, err := http.DefaultTransport.RoundTrip(req)
    if err != nil {
        http.Error(w, err.Error(), http.StatusServiceUnavailable)
        return
    }
    defer resp.Body.Close()
    copyHeader(w.Header(), resp.Header)
    w.WriteHeader(resp.StatusCode)
    io.Copy(w, resp.Body)
}

func copyHeader(dst, src http.Header) {
    for k, vv := range src {
        for _, v := range vv {
            dst.Add(k, v)
        }
    }
}

func basicAuth(username, password, realm string) func(http.Handler) http.Handler {
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
            
            if subtle.ConstantTimeCompare([]byte(pair[0]), []byte(username)) != 1 ||
               subtle.ConstantTimeCompare([]byte(pair[1]), []byte(password)) != 1 {
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
    defer file.Close()

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
            Port:     "8080",
            Username: "username",
            Password: "password",
            Realm:    "Proxy",
        }

        file, err := os.Create(filename)
        if err != nil {
            return err
        }
        defer file.Close()

        encoder := json.NewEncoder(file)
        encoder.SetIndent("", "    ")
        if err := encoder.Encode(defaultConfig); err != nil {
            return err
        }

        log.Printf("%s configuration file created with default values", filename)
    }

    return nil
}

func main() {
	configFile := "config.json"

    if err := createDefaultConfigIfNotExist(configFile); err != nil {
        log.Fatalf("Error when creating configuration file : %v", err)
    }

    config, err := loadConfig(configFile)
    if err != nil {
        log.Fatalf("Error while loading configuration : %v", err)
    }

    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        clientIP := getClientIP(r)
        log.Printf("Incoming request: %s %s from IP: %s", r.Method, r.URL, clientIP)
        if r.Method == http.MethodConnect {
            handleTunneling(w, r)
        } else {
            handleHTTP(w, r)
        }
    })

    authenticatedHandler := basicAuth(config.Username, config.Password, config.Realm)(handler)

    server := &http.Server{
        Addr:    ":" + config.Port,
        Handler: authenticatedHandler,
        TLSConfig: &tls.Config{
            InsecureSkipVerify: true,
        },
    }

    log.Printf("Start listening for requests on port %s\n", server.Addr)
    log.Fatal(server.ListenAndServe())
}