package vrandom

import (
	"fmt"
	"time"
)

func CrackMTSeededByRecentTime(mtCreator func(seed uint32) MersenneTwister, firstRand uint32, timeLimitInSeconds int) (uint32, error) {
	now := time.Now().Unix()

	for i := 0; i < timeLimitInSeconds; i++ {
		guessedSeed := uint32(now - int64(i))
		mt := mtCreator(guessedSeed)
		if mt.Rand() == firstRand {
			return guessedSeed, nil
		}
	}
	return 0, fmt.Errorf("Couldn't find seed in last %d seconds", timeLimitInSeconds)
}

func (mt *MersenneTwister) untemper(z uint32) uint32 {
	y := unshiftRight(z, mt.l, 0xFFFFFFFF)
	y = unshiftLeft(y, mt.t, mt.c)
	y = unshiftLeft(y, mt.s, mt.b)
	x := unshiftRight(y, mt.u, mt.d)
	return x
}

func unshiftLeft(y, shiftAmount, andValue uint32) uint32 {
	unshiftedNum := y
	for i := 0; i < 32; i++ {
		mask := uint32(1 << uint32(i))
		unshiftedNum ^= mask & andValue & (unshiftedNum << shiftAmount)
	}
	return unshiftedNum
}

func unshiftRight(z, shiftAmount, andValue uint32) uint32 {
	unshiftedNum := z
	for i := 32; i >= 0; i-- {
		mask := uint32(1 << uint32(i))
		unshiftedNum ^= mask & andValue & (unshiftedNum >> shiftAmount)
	}
	return unshiftedNum
}

func RecreateMTFromOutput(mt MersenneTwister) MersenneTwister {
	newMt := NewMersenneTwister(0)
	for i := uint32(0); i < mt.n; i++ {
		nextInt := mt.Rand()
		untempered := mt.untemper(nextInt)
		newMt.state[i] = untempered
	}
	return newMt
}
