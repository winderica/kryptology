package zk_r_affran

import (
	"crypto/rand"
	"math/big"

	"github.com/The9born/kryptology/pkg/tecdsa/2ecdsa/mta/paillier/zk"
	"github.com/gtank/merlin"
)

// The prover and the verifier should have already agreed on q, N0, g0, h0, N, c.
type Agreed struct {
	q  *big.Int
	N0 *big.Int
	g  *big.Int
	h  *big.Int
	N  *big.Int
	c  *big.Int

	NN       *big.Int
	N_plus_1 *big.Int
	K        *big.Int
}

// c_A
type Statement = big.Int

type Witness struct {
	a     *big.Int
	alpha *big.Int
}

func NewAgreed(q *big.Int, N0 *big.Int, g *big.Int, h *big.Int, N *big.Int, c_B *big.Int) *Agreed {
	NN := new(big.Int).Mul(N, N)
	N_plus_1 := new(big.Int).Add(N, big.NewInt(1))
	k := new(big.Int).Lsh(new(big.Int).Mul(q, q), zk.T+zk.L+zk.S)
	c := zk.Commit(c_B, N_plus_1, big.NewInt(1), new(big.Int).Lsh(q, zk.T+zk.L), NN)
	return &Agreed{q, N0, g, h, N, c, NN, N_plus_1, k}
}

func NewWitness(a *big.Int, alpha *big.Int) *Witness {
	return &Witness{a, alpha}
}

type Proof struct {
	A  *big.Int
	B1 *big.Int
	B2 *big.Int
	B3 *big.Int
	B4 *big.Int

	z1 *big.Int
	z2 *big.Int
	z3 *big.Int
	z4 *big.Int
}

func Prove(tx *merlin.Transcript, pp *Agreed, ws *Witness, c_A *Statement) *Proof {
	tx.AppendMessage([]byte("c_A"), c_A.Bytes()) // Strong Fiat-Shamir

	// Step 1: Commit
	b, _ := rand.Int(rand.Reader, new(big.Int).Lsh(pp.q, zk.T+zk.L))
	beta, _ := rand.Int(rand.Reader, new(big.Int).Lsh(pp.K, zk.T+zk.L))
	rho1, _ := rand.Int(rand.Reader, new(big.Int).Lsh(pp.N0, zk.T+zk.L))
	rho2, _ := rand.Int(rand.Reader, new(big.Int).Lsh(pp.N0, zk.T+zk.L))
	rho3, _ := rand.Int(rand.Reader, pp.N0)
	rho4, _ := rand.Int(rand.Reader, pp.N0)
	A := zk.Commit(pp.c, pp.N_plus_1, b, beta, pp.NN)
	B1 := zk.Commit(pp.g, pp.h, b, rho1, pp.N0)
	B2 := zk.Commit(pp.g, pp.h, beta, rho2, pp.N0)
	B3 := zk.Commit(pp.g, pp.h, ws.a, rho3, pp.N0)
	B4 := zk.Commit(pp.g, pp.h, ws.alpha, rho4, pp.N0)
	tx.AppendMessage([]byte("A"), A.Bytes())
	tx.AppendMessage([]byte("B1"), B1.Bytes())
	tx.AppendMessage([]byte("B2"), B2.Bytes())
	tx.AppendMessage([]byte("B3"), B3.Bytes())
	tx.AppendMessage([]byte("B4"), B4.Bytes())

	// Step 2: Challenge (Fiat-Shamir)
	e := new(big.Int).SetBytes(tx.ExtractBytes([]byte("e"), zk.T/8))

	// Step 3: Prove
	z1 := new(big.Int).Add(b, new(big.Int).Mul(e, ws.a))
	z2 := new(big.Int).Add(beta, new(big.Int).Mul(e, ws.alpha))
	z3 := new(big.Int).Add(rho1, new(big.Int).Mul(e, rho3))
	z4 := new(big.Int).Add(rho2, new(big.Int).Mul(e, rho4))

	return &Proof{A, B1, B2, B3, B4, z1, z2, z3, z4}
}

func Verify(tx *merlin.Transcript, pp *Agreed, c_A *Statement, proof *Proof) bool {
	tx.AppendMessage([]byte("c_A"), c_A.Bytes()) // Strong Fiat-Shamir

	tx.AppendMessage([]byte("A"), proof.A.Bytes())
	tx.AppendMessage([]byte("B1"), proof.B1.Bytes())
	tx.AppendMessage([]byte("B2"), proof.B2.Bytes())
	tx.AppendMessage([]byte("B3"), proof.B3.Bytes())
	tx.AppendMessage([]byte("B4"), proof.B4.Bytes())

	// Step 2: Challenge (Fiat-Shamir)
	e := new(big.Int).SetBytes(tx.ExtractBytes([]byte("e"), zk.T/8))

	// Step 4: Verify
	if proof.z1.Cmp(new(big.Int).Lsh(pp.q, zk.T+zk.L)) != -1 {
		return false
	}
	if proof.z1.Cmp(new(big.Int).Lsh(pp.q, zk.T)) == -1 {
		return false
	}
	if proof.z2.Cmp(new(big.Int).Lsh(pp.K, zk.T+zk.L)) == 1 {
		return false
	}
	if proof.z2.Cmp(new(big.Int).Lsh(pp.K, zk.T)) == -1 {
		return false
	}
	if zk.Commit(pp.c, pp.N_plus_1, proof.z1, proof.z2, pp.NN).Cmp(zk.Commit(proof.A, c_A, big.NewInt(1), e, pp.NN)) != 0 {
		return false
	}
	if zk.Commit(pp.g, pp.h, proof.z1, proof.z3, pp.N0).Cmp(zk.Commit(proof.B1, proof.B3, big.NewInt(1), e, pp.N0)) != 0 {
		return false
	}
	if zk.Commit(pp.g, pp.h, proof.z2, proof.z4, pp.N0).Cmp(zk.Commit(proof.B2, proof.B4, big.NewInt(1), e, pp.N0)) != 0 {
		return false
	}
	return true
}
