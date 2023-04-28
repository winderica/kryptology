package zk_qrdl

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/The9born/kryptology/pkg/tecdsa/2ecdsa/mta/paillier/zk"
	"github.com/gtank/merlin"
)

// The prover and the verifier should have already agreed on N and h.
type Agreed struct {
	N *big.Int
	h *big.Int
}

type Proof struct {
	z [zk.T]*big.Int
	e *big.Int
}

// g
type Statement = big.Int

type Witness struct {
	alpha *big.Int
}

func NewAgreed(N *big.Int, h *big.Int) *Agreed {
	return &Agreed{N, h}
}

func NewWitness(alpha *big.Int) *Witness {
	return &Witness{alpha}
}

func Prove(tx *merlin.Transcript, pp *Agreed, witness *Witness, g *Statement) *Proof {
	tx.AppendMessage([]byte("g"), g.Bytes()) // Strong Fiat-Shamir

	// Step 1: Commit
	n := new(big.Int).Lsh(pp.N, zk.S)
	beta := [zk.T]*big.Int{}
	a := [zk.T]*big.Int{}
	for i := 0; i < zk.T; i++ {
		b, _ := rand.Int(rand.Reader, n)             // b <$- [0, 2^s * N0)
		beta[i] = new(big.Int).Add(b, big.NewInt(1)) // beta <$- [1, 2^s * N0]
		a[i] = new(big.Int).Exp(pp.h, beta[i], pp.N) // a = h^beta % N0
		tx.AppendMessage([]byte(fmt.Sprintf("a[%d]", i)), a[i].Bytes())
	}

	// Step 2: Challenge (Fiat-Shamir)
	e := new(big.Int).SetBytes(tx.ExtractBytes([]byte("e"), zk.T/8))

	// Step 3: Prove
	z := [zk.T]*big.Int{}
	for i := 0; i < zk.T; i++ {
		// z = h_sqrt^e * r % N0
		if e.Bit(i) == 0 {
			z[i] = beta[i]
		} else {
			z[i] = new(big.Int).Add(witness.alpha, beta[i])
		}
	}

	return &Proof{z, e}
}

func Verify(tx *merlin.Transcript, pp *Agreed, g *Statement, proof *Proof) bool {
	tx.AppendMessage([]byte("g"), g.Bytes()) // Strong Fiat-Shamir

	// Step 4: Verify (Optimized)
	for i := 0; i < zk.T; i++ {
		// a = h^z / g^e % N0
		a := new(big.Int).Exp(pp.h, proof.z[i], pp.N)
		if proof.e.Bit(i) == 1 {
			a = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).ModInverse(g, pp.N), a), pp.N)
		}
		tx.AppendMessage([]byte(fmt.Sprintf("a[%d]", i)), a.Bytes())
	}

	// Step 2: Challenge (Fiat-Shamir)
	e := new(big.Int).SetBytes(tx.ExtractBytes([]byte("e"), zk.T/8))

	return e.Cmp(proof.e) == 0 // Compare the actual challenge with the alleged one
}
