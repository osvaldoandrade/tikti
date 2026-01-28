// controllers/async_runner.go
package controllers

import (
	"context"
)

// asyncFunc represents a controller workload that accepts a context and returns a result or error.
type asyncFunc func(ctx context.Context) (interface{}, error)

// runCommandAsync executes the given workload on a goroutine and returns a buffered result channel.
func runCommandAsync(fn asyncFunc) <-chan interface{} {
	out := make(chan interface{}, 1)
	go func() {
		defer close(out)
		result, err := fn(context.Background())
		if err != nil {
			out <- err
			return
		}
		out <- result
	}()
	return out
}
