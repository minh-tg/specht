package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

const healthcheckTimeout = 2 * time.Second

// healthcheckURL turns the server's listen address into the URL a probe on
// the same host should hit. Wildcard and empty hosts mean "every interface",
// which the loopback address reaches.
func healthcheckURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		host, port = "", "8080"
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/api/v1/health"
}

// runHealthcheck reports an error unless url answers 200 within timeout.
func runHealthcheck(url string, timeout time.Duration) error {
	resp, err := (&http.Client{Timeout: timeout}).Get(url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint answered %s", resp.Status)
	}
	return nil
}

// healthcheckMain backs `specht healthcheck`, the container HEALTHCHECK. It
// needs no database or secrets, only the listen address, so it can run in the
// minimal runtime image without a separate HTTP client binary.
func healthcheckMain() int {
	if err := runHealthcheck(healthcheckURL(os.Getenv("SERVER_ADDR")), healthcheckTimeout); err != nil {
		fmt.Fprintln(os.Stderr, "unhealthy:", err)
		return 1
	}
	return 0
}
