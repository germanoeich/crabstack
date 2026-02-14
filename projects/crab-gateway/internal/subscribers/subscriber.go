package subscribers

import (
	"context"

	"crabstack.local/projects/crab-sdk/types"
)

type Subscriber interface {
	Name() string
	Handle(context.Context, types.EventEnvelope) error
}
