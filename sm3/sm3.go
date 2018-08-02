package sm3

import (
	"encoding/binary"
	"hash"
)

const (
	Size      = 32
	BlockSize = 64
	//T(j)：常量，随j的变化取不同的值
	t0 = 0x79cc4519
	t1 = 0x7a879d8a
	//IV：初始值，用于确定压缩函数寄存器的初态
	iv0 = 0x7380166f
	iv1 = 0x4914b2b9
	iv2 = 0x172442d7
	iv3 = 0xda8a0600
	iv4 = 0xa96f30bc
	iv5 = 0x163138aa
	iv6 = 0xe38dee4d
	iv7 = 0xb0fb0e4e
)

type sm3_ctx struct {
	digest [8]uint32
	num    uint64
	block  []byte
}

func New() hash.Hash {
	sm3 := new(sm3_ctx)
	sm3.Reset()
	return sm3
}

// clone
func clone(src *sm3_ctx) *sm3_ctx {
	sm3 := &sm3_ctx{num: src.num}
	sm3.digest[0] = src.digest[0]
	sm3.digest[1] = src.digest[1]
	sm3.digest[2] = src.digest[2]
	sm3.digest[3] = src.digest[3]
	sm3.digest[4] = src.digest[4]
	sm3.digest[5] = src.digest[5]
	sm3.digest[6] = src.digest[6]
	sm3.digest[7] = src.digest[7]
	sm3.block = make([]byte, len(src.block))
	copy(sm3.block, src.block)
	return sm3
}

// Reset clears the internal state by zeroing bytes in the state buffer.
// This can be skipped for a newly-created hash state; the default zero-allocated state is correct.
func (self *sm3_ctx) Reset() {
	self.digest[0] = iv0
	self.digest[1] = iv1
	self.digest[2] = iv2
	self.digest[3] = iv3
	self.digest[4] = iv4
	self.digest[5] = iv5
	self.digest[6] = iv6
	self.digest[7] = iv7
	self.num = 0
	self.block = []byte{}
}

// BlockSize, required by the hash.Hash interface.
// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (self *sm3_ctx) BlockSize() int {
	return BlockSize
}

// Size, required by the hash.Hash interface.
// Size returns the number of bytes Sum will return.
func (self *sm3_ctx) Size() int {
	return Size
}

// FF(j)：布尔函数，随j的变化取不同的表达式
// X^Y^Z  0≤j≤15
func ff0(x, y, z uint32) uint32 {
	return x ^ y ^ z
}

// FF(j)：布尔函数，随j的变化取不同的表达式
// (X & Y)|(X&Z)|(Y&Z) 16≤j≤63
func ff1(x, y, z uint32) uint32 {
	return (x & y) | (x & z) | (y & z)
}

// GG(j)：布尔函数，随j的变化取不同的表达式
// X^Y^Z  0≤j≤15
func gg0(x, y, z uint32) uint32 {
	return x ^ y ^ z
}

// GG(j)：布尔函数，随j的变化取不同的表达式
// （X & Y）|（~X&Z）16≤j≤63
func gg1(x, y, z uint32) uint32 {
	return (x & y) | (^x & z)
}

// 置换函数
// （X）= X^(X<<<9)^（X<<<17)
func p0(x uint32) uint32 {
	return x ^ rl(x, 9) ^ rl(x, 17)
}

// 置换函数
// （X）= X^(X<<<15)^（X<<<23)
func p1(x uint32) uint32 {
	return x ^ rl(x, 15) ^ rl(x, 23)
}

// 左旋运算
func rl(x uint32, n uint32) uint32 {
	n %= 32
	return (x<<n | x>>(32-n))
}

// 扩展消息
func extend(data []byte) (w [68]uint32, w1 [64]uint32) {
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(data[4*i : 4*(i+1)])
	}
	for i := 16; i < 68; i++ {
		w[i] = p1(w[i-16]^w[i-9]^rl(w[i-3], 15)) ^ rl(w[i-13], 7) ^ w[i-6]
	}
	for i := 0; i < 64; i++ {
		w1[i] = w[i] ^ w[i+4]
	}
	return w, w1
}

// cf is compress function
func (self *sm3_ctx) cf(w [68]uint32, w1 [64]uint32) {
	a := self.digest[0]
	b := self.digest[1]
	c := self.digest[2]
	d := self.digest[3]
	e := self.digest[4]
	f := self.digest[5]
	g := self.digest[6]
	h := self.digest[7]
	for i := 0; i < 16; i++ {
		ss1 := rl(rl(a, 12)+e+rl(t0, uint32(i)), 7)
		ss2 := ss1 ^ rl(a, 12)
		tt1 := ff0(a, b, c) + d + ss2 + w1[i]
		tt2 := gg0(e, f, g) + h + ss1 + w[i]
		d = c
		c = rl(b, 9)
		b = a
		a = tt1
		h = g
		g = rl(f, 19)
		f = e
		e = p0(tt2)
	}
	for i := 16; i < 64; i++ {
		ss1 := rl(rl(a, 12)+e+rl(t1, uint32(i)), 7)
		ss2 := ss1 ^ rl(a, 12)
		tt1 := ff1(a, b, c) + d + ss2 + w1[i]
		tt2 := gg1(e, f, g) + h + ss1 + w[i]
		d = c
		c = rl(b, 9)
		b = a
		a = tt1
		h = g
		g = rl(f, 19)
		f = e
		e = p0(tt2)
	}
	self.digest[0] ^= a
	self.digest[1] ^= b
	self.digest[2] ^= c
	self.digest[3] ^= d
	self.digest[4] ^= e
	self.digest[5] ^= f
	self.digest[6] ^= g
	self.digest[7] ^= h
}

// update, iterative compress, update digests
func (self *sm3_ctx) update(msg []byte, nblocks int) {
	for i := 0; i < nblocks; i++ {
		start := i * BlockSize
		w, w1 := extend(msg[start : start+BlockSize])
		self.cf(w, w1)
	}
}

// Write, required by the hash.Hash interface.
// Write (via the embedded io.Writer interface) adds more data to the running hash.
// It never returns an error.
func (self *sm3_ctx) Write(p []byte) (n int, err error) {
	n = len(p)
	self.num += uint64(n * 8)
	msg := append(self.block, p...)
	nblocks := len(msg) / BlockSize
	self.update(msg, nblocks)
	self.block = msg[nblocks*BlockSize:]
	return n, nil
}

func (self *sm3_ctx) padding() []byte {
	msg := self.block
	msg = append(msg, 0x80)
	for len(msg)%BlockSize != 56 {
		msg = append(msg, 0x00)
	}
	msg = append(msg, uint8(self.num>>56&0xff))
	msg = append(msg, uint8(self.num>>48&0xff))
	msg = append(msg, uint8(self.num>>40&0xff))
	msg = append(msg, uint8(self.num>>32&0xff))
	msg = append(msg, uint8(self.num>>24&0xff))
	msg = append(msg, uint8(self.num>>16&0xff))
	msg = append(msg, uint8(self.num>>8&0xff))
	msg = append(msg, uint8(self.num>>0&0xff))
	if len(msg)%BlockSize != 0 {
		panic("padding error block length is " + string(len(msg)))
	}
	return msg
}

// Sum, required by the hash.Hash interface.
// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (self *sm3_ctx) Sum(in []byte) []byte {
	sm3 := clone(self)
	msg := sm3.padding()
	nblocks := len(msg) / BlockSize
	sm3.update(msg, nblocks)
	needed := Size
	if cap(in)-len(in) < needed {
		newIn := make([]byte, len(in), len(in)+needed)
		copy(newIn, in)
		in = newIn
	}
	out := in[len(in) : len(in)+needed]
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(out[i*4:], sm3.digest[i])
	}
	return out
}
