package merkle

import "math"

// BloomFilter implements a probabilistic set membership test
type BloomFilter struct {
	bitset    []uint64
	hashCount int
	bitSize   uint64
}

// NewBloomFilter creates a new bloom filter with given capacity and false positive rate
func NewBloomFilter(capacity int, falsePositiveRate float64) *BloomFilter {
	m := -float64(capacity) * math.Log(falsePositiveRate) / math.Pow(math.Log(2), 2)
	k := math.Ceil((m / float64(capacity)) * math.Log(2))

	bitSize := uint64(math.Ceil(m))
	wordCount := (bitSize + 63) / 64

	return &BloomFilter{
		bitset:    make([]uint64, wordCount),
		hashCount: int(k),
		bitSize:   bitSize,
	}
}

// Add adds an item to the bloom filter
func (bf *BloomFilter) Add(item []byte) {
	for i := 0; i < bf.hashCount; i++ {
		h := hash(item, uint32(i))
		position := h % bf.bitSize
		bf.setBit(position)
	}
}

// Test checks if an item might be in the set
func (bf *BloomFilter) Test(item []byte) bool {
	for i := 0; i < bf.hashCount; i++ {
		h := hash(item, uint32(i))
		position := h % bf.bitSize
		if !bf.getBit(position) {
			return false
		}
	}
	return true
}

// setBit sets a bit in the bitset
func (bf *BloomFilter) setBit(pos uint64) {
	wordIndex := pos / 64
	bitIndex := pos % 64
	bf.bitset[wordIndex] |= 1 << bitIndex
}

// getBit tests if a bit is set
func (bf *BloomFilter) getBit(pos uint64) bool {
	wordIndex := pos / 64
	bitIndex := pos % 64
	return (bf.bitset[wordIndex] & (1 << bitIndex)) != 0
}
