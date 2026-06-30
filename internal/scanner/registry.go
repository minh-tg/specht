package scanner

type Registry struct {
	parsers map[string]Parser
}

func NewRegistry() *Registry {
	return &Registry{parsers: make(map[string]Parser)}
}

func (r *Registry) Register(p Parser) {
	r.parsers[p.Name()] = p
}

func (r *Registry) Get(name string) (Parser, bool) {
	p, ok := r.parsers[name]
	return p, ok
}

func (r *Registry) Detect(data []byte) (Parser, bool) {
	for _, p := range r.parsers {
		d, ok := p.(interface{ Detect([]byte) bool })
		if ok && d.Detect(data) {
			return p, true
		}
	}
	return nil, false
}
