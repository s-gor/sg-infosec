package command

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/s-gor/sg-infosec/internal/web/app"
	"github.com/s-gor/sg-infosec/internal/web/auth"
	webconfig "github.com/s-gor/sg-infosec/internal/web/config"
	"github.com/s-gor/sg-infosec/internal/web/coreclient"
)

func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}

	flags := flag.NewFlagSet("sg-infosec-web", flag.ContinueOnError)
	flags.SetOutput(stderr)
	resetAdmin := flags.String("reset-admin", "", "reset administrator; password is read from stdin")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}

	cfg, err := webconfig.LoadFromEnv()
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return 1
	}
	store, err := auth.Open(cfg.StatePath, time.Now)
	if err != nil {
		fmt.Fprintf(stderr, "authentication state error: %v\n", err)
		return 1
	}

	if username := strings.TrimSpace(*resetAdmin); username != "" {
		password, err := readPassword(stdin)
		if err != nil {
			fmt.Fprintf(stderr, "password input error: %v\n", err)
			return 1
		}
		if err := store.ResetAdmin(username, password); err != nil {
			fmt.Fprintf(stderr, "administrator reset error: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "administrator reset; restart sg-infosec-web.service")
		return 0
	}

	handler, err := app.New(app.Config{BasePath: cfg.BasePath, SessionTTL: cfg.SessionTTL}, store, coreclient.New(cfg.ControlSocket))
	if err != nil {
		fmt.Fprintf(stderr, "web application error: %v\n", err)
		return 1
	}
	listener, err := listenUnix(cfg.ListenSocket)
	if err != nil {
		fmt.Fprintf(stderr, "listen error: %v\n", err)
		return 1
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(cfg.ListenSocket)
	}()

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	fmt.Fprintf(stdout, "SG InfoSec web listening on %s at %s\n", cfg.ListenSocket, cfg.BasePath)
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(stderr, "server error: %v\n", err)
		return 1
	}
	return 0
}

func readPassword(input io.Reader) (string, error) {
	reader := bufio.NewReader(io.LimitReader(input, 2049))
	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value = strings.TrimRight(value, "\r\n")
	if value == "" {
		return "", fmt.Errorf("password is empty")
	}
	if len(value) > 1024 {
		return "", fmt.Errorf("password is too long")
	}
	return value, nil
}

func listenUnix(path string) (net.Listener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket path %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect socket path: %w", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("chmod web socket: %w", err)
	}
	return listener, nil
}
