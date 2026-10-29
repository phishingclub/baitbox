package utils

// NonNil returns an empty slice for nil, so JSON encodes [] instead of null.
func NonNil[T any](in []T) []T {
	if in == nil {
		return []T{}
	}
	return in
}
