package zk_r_pwr

import (
	"crypto/rand"
	"math/big"

	"github.com/coinbase/kryptology/pkg/core"
	"github.com/The9born/kryptology/pkg/tecdsa/2ecdsa/mta/paillier/zk"

	"github.com/gtank/merlin"
)

// The prover and the verifier should have already agreed on q, N0, g0, h0, N.
type Agreed struct {
	q  *big.Int
	N0 *big.Int
	g0 *big.Int
	h0 *big.Int
	N  *big.Int

	NN       *big.Int
	N_plus_1 *big.Int
}

// c
type Statement = big.Int

type Witness struct {
	x *big.Int
	r *big.Int
}

type Proof struct {
	C  *big.Int
	d  *big.Int
	D  *big.Int

	z1 *big.Int
	z2 *big.Int
	z3 *big.Int
}

func NewAgreed(q *big.Int, N0 *big.Int, g0 *big.Int, h0 *big.Int, N *big.Int) *Agreed {
	NN := new(big.Int).Mul(N, N)
	N_plus_1 := new(big.Int).Add(N, core.One)

	return &Agreed{q, N0, g0, h0, N, NN, N_plus_1}
}

func NewWitness(x *big.Int, r *big.Int) *Witness {
	return &Witness{x, r}
}

func Prove(tx *merlin.Transcript, pp *Agreed, ws *Witness, c *Statement) *Proof {
	tx.AppendMessage([]byte("c"), c.Bytes()) // Strong Fiat-Shamir

	// Step 1: Commit
	alpha, _ := rand.Int(rand.Reader, pp.N0)                             // alpha <$- [0, N0)
	beta, _ := rand.Int(rand.Reader, new(big.Int).Lsh(pp.N0, zk.T+zk.L)) // beta <$- [0, N0 << (t + l))
	y, _ := rand.Int(rand.Reader, new(big.Int).Lsh(pp.q, zk.T+zk.L))     // y <$- [0, q << (t + l))
	r_d, _ := rand.Int(rand.Reader, pp.N)                                // r_d <$- [0, N)
	C := zk.Commit(pp.g0, pp.h0, ws.x, alpha, pp.N0)                     // C = g^x * h^alpha % N0
	d := zk.Commit(r_d, pp.N_plus_1, pp.N, y, pp.NN)                     // d = r_d^N * (N + 1)^y % N^2
	D := zk.Commit(pp.g0, pp.h0, y, beta, pp.N0)                         // D = g^y * h^beta % N0
	tx.AppendMessage([]byte("C"), C.Bytes())
	tx.AppendMessage([]byte("d"), d.Bytes())
	tx.AppendMessage([]byte("D"), D.Bytes())

	// Step 2: Challenge (Fiat-Shamir)
	e := new(big.Int).SetBytes(tx.ExtractBytes([]byte("e"), zk.T/8))

	// Step 3: Prove
	z1 := new(big.Int).Add(y, new(big.Int).Mul(e, ws.x))
	z2 := zk.Commit(r_d, ws.r, big.NewInt(1), e, pp.N)
	z3 := new(big.Int).Add(beta, new(big.Int).Mul(e, alpha))

	return &Proof{C, d, D, z1, z2, z3}
}

func Verify(tx *merlin.Transcript, pp *Agreed, c *Statement, proof *Proof) bool {
	tx.AppendMessage([]byte("c"), c.Bytes()) // Strong Fiat-Shamir

	tx.AppendMessage([]byte("C"), proof.C.Bytes())
	tx.AppendMessage([]byte("d"), proof.d.Bytes())
	tx.AppendMessage([]byte("D"), proof.D.Bytes())

	// Step 2: Challenge (Fiat-Shamir)
	e := new(big.Int).SetBytes(tx.ExtractBytes([]byte("e"), zk.T/8))

	// Step 4: Verify
	if zk.Commit(proof.z2, pp.N_plus_1, pp.N, proof.z1, pp.NN).Cmp(zk.Commit(proof.d, c, big.NewInt(1), e, pp.NN)) != 0 {
		return false
	}
	if zk.Commit(pp.g0, pp.h0, proof.z1, proof.z3, pp.N0).Cmp(zk.Commit(proof.D, proof.C, big.NewInt(1), e, pp.N0)) != 0 {
		return false
	}
	if proof.z1.Cmp(new(big.Int).Lsh(pp.q, zk.T)) == -1 {
		return false
	}
	if proof.z1.Cmp(new(big.Int).Lsh(pp.q, zk.T+zk.L)) != -1 {
		return false
	}
	return true
}
