package vecindex

import (
	"sync/atomic"

	"github.com/coder/hnsw"
)

// Package vecindex exposes a small abstraction backed by github.com/coder/hnsw.
// HNSW indexes and searches vectors that you provide.
// HNSW performs nearest-neighbor search in approximately O(log n) time, so it is fast.

// Index is a minimal vector index interface.
type Index interface {
	// Add inserts a vector under the given id.
	Add(id string, vec []float32) error
	// Count returns the number of vectors stored.
	Count() int
	// Search returns up to k nearest neighbor IDs for the provided vector.
	Search(vec []float32, k int) ([]string, error)
}

// hnswIndex wraps coder/hnsw for in-memory vector indexing.
type hnswIndex struct {
	g      *hnsw.Graph[uint32]
	nextID uint32
	// mappings and raw vectors (used for simple linear search for now)
	id2node map[string]uint32
	node2id map[uint32]string
	vecs    map[uint32][]float32
}

// NewSBOMVecIndex returns an HNSW-backed Index using cosine distance.
func NewSBOMVecIndex() Index {
	g := hnsw.NewGraph[uint32]()
	g.Distance = hnsw.CosineDistance
	// Reasonable small defaults for MVP; can be tuned later.
	g.M = 16
	g.Ml = 0.25
	g.EfSearch = 20
	return &hnswIndex{g: g, id2node: make(map[string]uint32), node2id: make(map[uint32]string), vecs: make(map[uint32][]float32)}
}

func (h *hnswIndex) Add(extID string, vec []float32) error {
	id := atomic.AddUint32(&h.nextID, 1) - 1
	n := hnsw.MakeNode(id, vec)
	h.g.Add(n)
	h.id2node[extID] = id
	h.node2id[id] = extID
	h.vecs[id] = vec
	return nil
}

func (h *hnswIndex) Count() int { return h.g.Len() }

// Search uses native HNSW search to retrieve up to k nearest neighbor IDs.
func (h *hnswIndex) Search(vec []float32, k int) ([]string, error) {
	if k <= 0 {
		return nil, nil
	}
	nodes := h.g.Search(vec, k)
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, h.node2id[n.Key])
	}
	return out, nil
}
