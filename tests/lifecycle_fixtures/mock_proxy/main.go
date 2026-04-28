// mock_proxy — controlled-behavior aikey-proxy stand-in for E2E lifecycle tests.
//
// Reads behavior switches from environment variables so tests can construct
// scenarios that the real proxy can't easily emulate (bind failure, /health
// hang, drain delay, SIGTERM ignore). Always accepts `--config <path>` as
// the real binary does so tests can swap binaries with no other change.
//
// **Why Go**: cross-platform (macOS / Linux / Windows) with no CGO; tiny
// binary (~5 MB); standard net/http for /health endpoint; signal package
// for SIGTERM control. Per E2E plan v6 §3.1.
//
// Behavior switches (env vars):
//   MOCK_LISTEN=1            (default) bind --port and accept connections
//   MOCK_HEALTH_OK=1         (default) /health returns 200
//   MOCK_BIND_FAIL=1         exit 1 immediately (simulates "port held")
//   MOCK_HANG_INIT=1         bind but /health hangs forever
//   MOCK_DRAIN_DELAY_SECS=N  on SIGTERM, sleep N seconds before exit (graceful drain sim)
//   MOCK_IGNORE_SIGTERM=1    completely ignore SIGTERM (only SIGKILL kills)
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

func envBool(key string, defaultVal bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return defaultVal
	}
	return v == "1" || v == "true"
}

func envInt(key string, defaultVal int) int {
	v := os.Getenv(key)
	if v == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return defaultVal
	}
	return n
}

func main() {
	configPath := flag.String("config", "", "path to aikey-proxy.yaml (parsed for listen.port)")
	flag.Parse()

	// MOCK_BIND_FAIL: exit immediately to simulate a config error or
	// port-bind failure. Tests use this for W3 (start_with_child_dies_at_init).
	if envBool("MOCK_BIND_FAIL", false) {
		fmt.Fprintln(os.Stderr, "[mock_proxy] MOCK_BIND_FAIL=1, exiting 1 immediately")
		os.Exit(1)
	}

	port := envInt("MOCK_PORT", 0)
	if port == 0 {
		// Try to read port from config file if --config given. We do a
		// simple grep — proper YAML parsing is overkill for the mock.
		if *configPath != "" {
			data, err := os.ReadFile(*configPath)
			if err == nil {
				for _, line := range splitLines(string(data)) {
					if portLine := extractPort(line); portLine > 0 {
						port = portLine
						break
					}
				}
			}
		}
	}
	if port == 0 {
		port = 27200 // sensible default matching the real proxy
	}

	listen := envBool("MOCK_LISTEN", true)
	healthOK := envBool("MOCK_HEALTH_OK", true)
	hangInit := envBool("MOCK_HANG_INIT", false)
	drainDelay := envInt("MOCK_DRAIN_DELAY_SECS", 0)
	ignoreSIGTERM := envBool("MOCK_IGNORE_SIGTERM", false)

	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// Set up SIGTERM handler. Tests use this for D2/D3/W1.
	sigCh := make(chan os.Signal, 1)
	if ignoreSIGTERM {
		// Block SIGTERM entirely so only SIGKILL can kill us.
		// Note: signal.Ignore doesn't actually block — we receive but do nothing.
		signal.Ignore(syscall.SIGTERM)
		fmt.Fprintln(os.Stderr, "[mock_proxy] MOCK_IGNORE_SIGTERM=1, SIGTERM will be ignored")
	} else {
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	}

	if !listen {
		// No port binding — just block until killed.
		fmt.Fprintln(os.Stderr, "[mock_proxy] MOCK_LISTEN=0, not binding port")
		<-sigCh
		os.Exit(0)
	}

	// Bind the port early so the test can detect the listen.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[mock_proxy] bind %s failed: %v\n", addr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[mock_proxy] listening on %s (drain_delay=%ds, hang_init=%v, ignore_sigterm=%v)\n",
		addr, drainDelay, hangInit, ignoreSIGTERM)

	// Track in-flight requests so tests can assert "we waited for the drain".
	var inFlight atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if hangInit {
			// MOCK_HANG_INIT: never respond. Test sees Unresponsive state.
			select {} // block forever
		}
		if healthOK {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"status":"ok"}`)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	// Catch-all for diagnostic — any other path is a stub.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		inFlight.Add(1)
		defer inFlight.Add(-1)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "mock_proxy")
	})

	srv := &http.Server{Handler: mux}
	go func() {
		_ = srv.Serve(ln)
	}()

	// Wait for shutdown signal.
	if ignoreSIGTERM {
		// Block forever — only SIGKILL ends us.
		select {}
	}

	<-sigCh
	fmt.Fprintf(os.Stderr, "[mock_proxy] received SIGTERM, in-flight=%d, draining for %ds\n",
		inFlight.Load(), drainDelay)

	if drainDelay > 0 {
		time.Sleep(time.Duration(drainDelay) * time.Second)
	}

	_ = ln.Close()
	fmt.Fprintln(os.Stderr, "[mock_proxy] exit 0")
	os.Exit(0)
}

func splitLines(s string) []string {
	out := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// extractPort handles `port: 27200` (with optional indent / quotes).
func extractPort(line string) int {
	// Find "port:" then parse the number after it.
	idx := indexOf(line, "port:")
	if idx < 0 {
		return 0
	}
	rest := line[idx+5:]
	// Strip whitespace + quotes.
	num := ""
	for _, c := range rest {
		if c >= '0' && c <= '9' {
			num += string(c)
		} else if num != "" {
			break
		}
	}
	if num == "" {
		return 0
	}
	n, err := strconv.Atoi(num)
	if err != nil {
		return 0
	}
	return n
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
