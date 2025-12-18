package e2e

import (
	"cmp"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3/http/e2e"
	"github.com/mccutchen/go-httpbin/v2/httpbin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestE2E(t *testing.T) {
	envoyImage := cmp.Or(os.Getenv("ENVOY_IMAGE"), "envoy-with-coraza-module:latest")

	cwd, err := os.Getwd()
	require.NoError(t, err)

	// Setup the httpbin upstream local server.
	httpbinHandler := httpbin.New()
	server := &http.Server{Addr: ":1234", Handler: httpbinHandler}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Logf("HTTP server error: %v", err)
		}
	}()
	t.Cleanup(func() { _ = server.Close() })

	err = os.WriteFile(filepath.Join(cwd, "rules.conf"), []byte(e2e.Directives), 0o644)
	require.NoError(t, err)

	cmd := exec.Command(
		"docker",
		"run",
		"--network", "host",
		"-v", cwd+":/e2e",
		"-w", "/e2e",
		"--rm",
		envoyImage,
		"--concurrency", "1",
		"--config-path", "/e2e/envoy.yaml",
		"--base-id", strconv.Itoa(time.Now().Nanosecond()),
	)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { require.NoError(t, cmd.Process.Signal(os.Interrupt)) })

	t.Run("run coraza tests", func(t *testing.T) {
		err := e2e.Run(e2e.Config{
			NulledBody:        false,
			ProxiedEntrypoint: "http://localhost:10000",
			HttpbinEntrypoint: "http://localhost:1234",
		})
		assert.NoError(t, err)
	})
}
