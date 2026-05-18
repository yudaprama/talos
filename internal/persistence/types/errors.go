package persistencetypes

import "errors"

// ErrKeyNotActive is returned by RotateIssuedAPIKeyAtomic when the key exists
// but is not in active status (e.g. already revoked). Callers should map this
// to a 409 FailedPrecondition response.
var ErrKeyNotActive = errors.New("key exists but is not active")
