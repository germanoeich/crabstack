package subscribers

import (
	"context"

	"crabstack.local/lib/types"
)

type Subscriber interface {
	Name() string
	Handle(context.Context, types.EventEnvelope) error
}
