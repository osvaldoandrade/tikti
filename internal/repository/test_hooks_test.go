package repository

import (
	"context"
	"strings"

	"github.com/go-redis/redis/v8"
)

type commandErrorHook struct {
	byName map[string]error
}

func (h commandErrorHook) BeforeProcess(ctx context.Context, cmd redis.Cmder) (context.Context, error) {
	if h.byName == nil {
		return ctx, nil
	}
	if err, ok := h.byName[strings.ToLower(cmd.Name())]; ok {
		return ctx, err
	}
	return ctx, nil
}

func (h commandErrorHook) AfterProcess(context.Context, redis.Cmder) error {
	return nil
}

func (h commandErrorHook) BeforeProcessPipeline(ctx context.Context, cmds []redis.Cmder) (context.Context, error) {
	for _, cmd := range cmds {
		if nextCtx, err := h.BeforeProcess(ctx, cmd); err != nil {
			return nextCtx, err
		}
	}
	return ctx, nil
}

func (h commandErrorHook) AfterProcessPipeline(context.Context, []redis.Cmder) error {
	return nil
}
