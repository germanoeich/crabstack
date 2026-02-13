package pairing

import "errors"

var (
	ErrInvalidRequest          = errors.New("invalid pairing request")
	ErrUnsupportedComponent    = errors.New("unsupported component type")
	ErrMTLSRequired            = errors.New("mtls is required for remote pairing")
	ErrProtocolViolation       = errors.New("pairing protocol violation")
	ErrSignatureVerification   = errors.New("signature verification failed")
	ErrChallengeMismatch       = errors.New("challenge mismatch")
	ErrRemoteReturnedPairError = errors.New("remote returned pair.error")
)
