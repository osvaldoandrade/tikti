// Package testredis owns an isolated, non-persistent Redis process for contract
// tests. Production entrypoints do not import this package.
package testredis

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/go-redis/redis/v8"
)

type Server struct {
	URL    string
	Client *redis.Client
	dir    string
	cmd    *exec.Cmd
	done   chan error
	once   sync.Once
}

// Start requires redis-server on PATH. Missing Redis is a failure, never a
// skipped integration suite. A private Unix socket prevents network exposure.
func Start() (*Server, error) {
	dir, err := os.MkdirTemp("", "tikti-redis-")
	if err != nil {
		return nil, errors.New("create isolated Redis directory")
	}
	socket := filepath.Join(dir, "r.sock")
	// All arguments are fixed test settings or a newly created private path.
	cmd := exec.Command("redis-server", "--port", "0", "--unixsocket", socket, "--unixsocketperm", "700", "--save", "", "--appendonly", "no", "--daemonize", "no", "--dir", dir) // #nosec G204 -- isolated test dependency, no caller command or arguments.
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	server := &Server{URL: "unix://" + socket, dir: dir, cmd: cmd, done: make(chan error, 1)}
	server.Client = redis.NewClient(&redis.Options{Network: "unix", Addr: socket, MaxRetries: -1, DialTimeout: 100 * time.Millisecond, ReadTimeout: time.Second, WriteTimeout: time.Second})
	if err := cmd.Start(); err != nil {
		_ = server.Client.Close()
		_ = os.RemoveAll(dir)
		return nil, errors.New("start redis-server test dependency")
	}
	go func() { server.done <- cmd.Wait() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if server.Client.Ping(ctx).Err() == nil {
			return server, nil
		}
		select {
		case <-ctx.Done():
			server.Close()
			return nil, errors.New("isolated Redis startup timed out")
		case <-ticker.C:
		}
	}
}

func (s *Server) Close() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		_ = s.Client.Close()
		_ = s.cmd.Process.Signal(syscall.SIGTERM)
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case <-s.done:
		case <-timer.C:
			_ = s.cmd.Process.Kill()
			<-s.done
		}
		_ = os.RemoveAll(s.dir)
	})
}
