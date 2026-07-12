package scanner

type Registry struct {
	scanners map[string]Scanner
}

func NewRegistry() *Registry {
	return &Registry{scanners: make(map[string]Scanner)}
}

func (r *Registry) Register(s Scanner) {
	r.scanners[s.Name()] = s
}

func (r *Registry) Get(name string) (Scanner, bool) {
	s, ok := r.scanners[name]
	return s, ok
}

func (r *Registry) Detect(data []byte) (Scanner, bool) {
	for _, s := range r.scanners {
		if s.DetectFormat(data) {
			return s, true
		}
	}
	return nil, false
}
