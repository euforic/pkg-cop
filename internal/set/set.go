package set

func New(values ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func Has(values map[string]struct{}, value string) bool {
	_, ok := values[value]
	return ok
}
