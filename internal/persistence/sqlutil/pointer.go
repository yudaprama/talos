package sqlutil

// Deref returns the dereferenced pointer value, or the zero value of T if nil.
func Deref[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}

// PtrOrNil returns a pointer to v, or nil if v is the zero value.
func PtrOrNil[T comparable](v T) *T {
	var zero T
	if v == zero {
		return nil
	}
	return &v
}

// NonNilSlice returns s if non-nil, otherwise an empty non-nil slice.
func NonNilSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// reviewed - @aeneasr - 2026-03-26
