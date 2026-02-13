package subscribers

import (
	"context"

	"pinchy.local/lib/types"
)

type Subscriber interface {
	Name() string
	Handle(context.Context, types.EventEnvelope) error
}
