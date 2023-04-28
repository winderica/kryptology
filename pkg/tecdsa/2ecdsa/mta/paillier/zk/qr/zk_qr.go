package zk_qr

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/The9born/kryptology/pkg/tecdsa/2ecdsa/mta/paillier/zk"
	"github.com/gtank/merlin"
)

// The prover and the verifier should have already agreed on N
type Agreed struct {
	N *big.Int
}

type Proof struct {
	z [zk.T]*big.Int
	e *big.Int
}

// h
type Statement = big.Int

type Witness struct {
	h_sqrt *big.Int
}

func NewAgreed(N *big.Int) *Agreed {
	return &Agreed{N}
}

func NewWitness(h_sqrt *big.Int) *Witness {
	return &Witness{h_sqrt}
}

func Prove(tx *merlin.Transcript, pp *Agreed, witness *Witness, h *Statement) *Proof {
	tx.AppendMessage([]byte("h"), h.Bytes()) // Strong Fiat-Shamir

	// Step 1: Commit
	r := [zk.T]*big.Int{}
	a := [zk.T]*big.Int{}
	for i := 0; i < zk.T; i++ {
		r[i], _ = rand.Int(rand.Reader, pp.N)
		a[i] = new(big.Int).Mod(new(big.Int).Mul(r[i], r[i]), pp.N) // a = r^2 % N0
		tx.AppendMessage([]byte(fmt.Sprintf("a[%d]", i)), a[i].Bytes())
	}

	// Step 2: Challenge (Fiat-Shamir)
	e := new(big.Int).SetBytes(tx.ExtractBytes([]byte("e"), zk.T/8))

	// Step 3: Prove
	z := [zk.T]*big.Int{}
	for i := 0; i < zk.T; i++ {
		// z = h_sqrt^e * r % N0
		if e.Bit(i) == 0 {
			z[i] = r[i]
		} else {
			z[i] = new(big.Int).Mod(new(big.Int).Mul(r[i], witness.h_sqrt), pp.N)
		}
	}

	return &Proof{z, e}
}

func Verify(tx *merlin.Transcript, pp *Agreed, h *Statement, proof *Proof) bool {
	tx.AppendMessage([]byte("h"), h.Bytes()) // Strong Fiat-Shamir

	// Step 4: Verify (Optimized)
	for i := 0; i < zk.T; i++ {
		// a = z^2 / h^e % N0
		a := new(big.Int).Mod(new(big.Int).Mul(proof.z[i], proof.z[i]), pp.N)
		if proof.e.Bit(i) == 1 {
			a = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).ModInverse(h, pp.N), a), pp.N)
		}
		tx.AppendMessage([]byte(fmt.Sprintf("a[%d]", i)), a.Bytes())
	}

	// Step 2: Challenge (Fiat-Shamir)
	e := new(big.Int).SetBytes(tx.ExtractBytes([]byte("e"), zk.T/8))

	return e.Cmp(proof.e) == 0 // Compare the actual challenge with the alleged one
}
