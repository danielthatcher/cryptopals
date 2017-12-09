package util

type MT19337 struct {
	State      []uint64
	seed       uint64
	Index      uint64
	w          uint64
	n          uint64
	m          uint64
	r          uint64
	a          uint64
	u          uint64
	d          uint64
	s          uint64
	b          uint64
	t          uint64
	c          uint64
	I          uint64
	upper_mask uint64
	lower_mask uint64
}

func (r *MT19337) Init(seed uint64) {
	r.w = 32
	r.n = 624
	r.m = 397
	r.r = 31
	r.a = 0x9908B0DF
	r.u = 11
	r.d = 0xFFFFFFFF
	r.s = 7
	r.b = 0x9D2C5680
	r.t = 15
	r.c = 0xEFC60000
	r.I = 18
	r.lower_mask = 0x7fffffff
	r.upper_mask = 0x80000000
	r.Index = r.n + 1
	r.State = make([]uint64, r.n)
	r.seed = seed
	r.State[0] = seed & 0xffffffff
	for i := 1; i < len(r.State); i++ {
		r.State[i] = (1812433253*(r.State[i-1]^(r.State[i-1]>>30)) + uint64(i))
		r.State[i] = r.State[i] & 0xffffffff
	}
	r.Index = r.n + 1
}

func (r *MT19337) NextInt() uint64 {
	// Reset state if necessary
	if r.Index >= r.n {
		mag01 := []uint64{0, r.a}
		if r.Index == r.n+1 {
			r.Init(r.seed)
		}

		// First loop
		for k := uint64(0); k < r.n-r.m; k++ {
			y := (r.State[k] & r.upper_mask) | (r.State[k+1] & r.lower_mask)
			r.State[k] = r.State[k+r.m] ^ (y >> 1) ^ mag01[y&1]
		}

		// Second loop
		for k := r.n - r.m; k < r.n-1; k++ {
			y := (r.State[k] & r.upper_mask) | (r.State[k+1] & r.lower_mask)
			r.State[k] = r.State[k+r.m-r.n] ^ (y >> 1) ^ mag01[y&1]
		}

		y := (r.State[r.n-1] & r.upper_mask) | (r.State[0] & r.lower_mask)
		r.State[r.n-1] = r.State[r.n-1] ^ (y >> 1) ^ mag01[y&1]
		r.Index = 0
	}

	y := r.State[r.Index]
	r.Index += 1
	y ^= (y >> 11)
	y ^= (y << 7) & r.b
	y ^= (y << 15) & r.c
	y ^= (y >> 18)

	return y
}

func NewMT19337(seed uint64) *MT19337 {
	m := MT19337{}
	m.Init(seed)
	return &m
}

func NewMT19337State(state []uint64) *MT19337 {
	m := MT19337{}
	m.Init(0)
	m.Index = 0
	m.State = state
	return &m
}
