package traefik_guard

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Config the plugin configuration.
type Config struct {
	GuardUrl   string `json:"guardUrl,omitempty"`
	SkipVerify bool   `json:"skipVerify"`
	TimeoutMs  int    `json:"timeoutMs"`
	FailOpen   bool   `json:"failOpen"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		// TimeoutMs:  1000, 
		FailOpen:   false,
		SkipVerify: true,
	}
}

type Guard struct {
	next     http.Handler
	guardUrl string
	name     string
	config   *Config
	http     *http.Client
	logger   *log.Logger
}

// New created a new Guard plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.GuardUrl) == 0 {
		return nil, fmt.Errorf("GuardUrl cannot be empty")
	}

	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: config.SkipVerify}

	// Net client is a custom client to timeout after 2 seconds if the service is not ready
	var http = &http.Client{
		Transport: customTransport,
		Timeout:   5 * time.Second,
	}

	return &Guard{
		guardUrl: config.GuardUrl,
		next:     next,
		name:     name,
		http:     http,
		config:   config,
		logger:   log.New(os.Stdout, "", log.LstdFlags),
	}, nil
}

type RequestData struct {
	method       string            `json:"method"`
	uri          string            `json:"uri"`
	headers      map[string]string `json:"headers"`
	remote_addr  string            `json:"remote_addr"`
	http_version string            `json:"http_version"`
	scheme       string            `json:"scheme"`
}

func (a *Guard) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	// Websocket not supported
	if isWebsocket(req) {
		a.next.ServeHTTP(rw, req)
		return
	}

	headers := make(map[string]string)
	for k, v := range req.Header {
		headers[k] = strings.Join(v, ", ")
	}

	request_data := RequestData{
		method:       req.Method,
		uri:          req.URL.RequestURI(),
		headers:      headers,
		remote_addr:  req.RemoteAddr,
		http_version: req.Proto,
		scheme:       req.URL.Scheme,
	}

	data, err := json.Marshal(request_data)

	a.logger.Printf("json: %s", data)

	proxyReq, err := http.NewRequest(req.Method, a.guardUrl, bytes.NewReader(data))

	if err != nil {
		a.logger.Printf("fail to prepare forwarded request: %s", err.Error())
		http.Error(rw, "", http.StatusBadGateway)
		return
	}

	resp, err := a.http.Do(proxyReq)
	if err != nil {
		a.logger.Printf("fail to send HTTP request to guard: %s", err.Error())
		http.Error(rw, "", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		forwardResponse(resp, rw)
		return
	}

	a.next.ServeHTTP(rw, req)
}

func isWebsocket(req *http.Request) bool {
	for _, header := range req.Header["Upgrade"] {
		if header == "websocket" {
			return true
		}
	}
	return false
}

func forwardResponse(resp *http.Response, rw http.ResponseWriter) {
	// copy headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			rw.Header().Set(k, v)
		}
	}
	// copy status
	rw.WriteHeader(resp.StatusCode)
	// copy body
	io.Copy(rw, resp.Body)
}
