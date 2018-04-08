package vrandom

// MersenneTwister is created by the spec on wikipedia (https://en.wikipedia.org/wiki/Mersenne_Twister)
type MersenneTwister struct {
	w uint32
	n uint32
	m uint32
	r uint32

	a uint32
	b uint32
	c uint32
	s uint32
	t uint32
	u uint32
	d uint32
	l uint32
	f uint32

	idx   uint32
	state []uint32
}

func NewMersenneTwister(seed uint32) MersenneTwister {
	mt := MersenneTwister{
		w: 32,
		n: 624,
		m: 397,
		r: 31,

		a: 0x9908B0DF,
		b: 0x9D2C5680,
		c: 0xEFC60000,
		s: 7,
		t: 15,
		u: 11,
		d: 0xFFFFFFFF,
		l: 18,
		f: 1812433253,
	}

	mt.initialize(seed)

	return mt
}

func (mt *MersenneTwister) Rand() uint32 {
	// State for standard MT19937
	if mt.idx == uint32(len(mt.state)) {
		mt.generateNumbers()
	}
	return mt.extractNumber()
}

func (mt *MersenneTwister) extractNumber() uint32 {
	x := mt.state[mt.idx%mt.n]
	mt.idx++
	// Tempering transform
	y := x ^ ((x >> mt.u) & mt.d)
	y = y ^ ((y << mt.s) & mt.b)
	y = y ^ ((y << mt.t) & mt.c)
	z := y ^ (y >> mt.l)
	return z
}

func (mt *MersenneTwister) generateNumbers() {
	for k := uint32(0); k < mt.n; k++ {
		kPlusM := (k + mt.m) % mt.n
		concatenation := mt.concatenateKthIndex(k)
		mt.state[k] = mt.state[kPlusM] ^ (mt.multiplyByA(concatenation))
	}
}

func (mt *MersenneTwister) initialize(seed uint32) {
	mt.state = make([]uint32, mt.n)
	mt.state[0] = seed
	for i := uint32(1); i < mt.n; i++ {
		mt.state[i] = mt.f*(mt.state[i-1]^(mt.state[i-1]>>(mt.w-2))) + i
	}
	// The first value that is generated is based on x_i, not on x_0
	mt.generateNumbers()
}

func (mt MersenneTwister) multiplyByA(x uint32) uint32 {
	if x%2 == 0 {
		return x >> 1
	}
	return (x >> 1) ^ mt.a
}

func (mt MersenneTwister) concatenateKthIndex(k uint32) uint32 {
	// return the top w-r bits of x_k and the bottom r bits of x_k+1
	allOnes := uint32(0xFFFFFFFF)
	upperBitMask := allOnes << (mt.r)
	lowerBitMask := allOnes >> (mt.w - mt.r)
	upperBits := (mt.state[k] & upperBitMask)
	lowerBits := (mt.state[(k+1)%mt.n] & lowerBitMask)
	return upperBits | lowerBits
}
