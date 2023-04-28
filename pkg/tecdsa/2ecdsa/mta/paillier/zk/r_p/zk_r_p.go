package zk_r_p

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"

	"github.com/The9born/kryptology/pkg/tecdsa/2ecdsa/mta/paillier/zk"
	"github.com/gtank/merlin"
)

// Nothing needs to be agreed beforehand
type Agreed struct {
}

type Proof struct {
	w *big.Int

	x [zk.T]*big.Int
	a [zk.T]bool
	b [zk.T]bool
	z [zk.T]*big.Int
}

// N
type Statement = big.Int

type Witness struct {
	p *big.Int
	q *big.Int
}

func NewWitness(p *big.Int, q *big.Int) *Witness {
	return &Witness{p, q}
}

func Prove(tx *merlin.Transcript, witness *Witness, N *Statement) *Proof {
	tx.AppendMessage([]byte("N"), N.Bytes()) // Strong Fiat-Shamir

	// Step 1: Commit
	var w *big.Int
	for {
		w, _ = rand.Int(rand.Reader, N)
		if big.Jacobi(w, N) == -1 {
			break
		}
	}
	tx.AppendMessage([]byte("w"), w.Bytes())

	// Step 2: Challenge (Fiat-Shamir)
	y := [zk.T]*big.Int{}
	t := big.NewInt(0)
	tt := big.NewInt(0)
	for i := 0; i < zk.T; {
		if tt.Cmp(N) == -1 {
			v := new(big.Int).SetBytes(tx.ExtractBytes([]byte(fmt.Sprintf("y[%d]", i)), zk.N_BITS/8+1))
			vv := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), zk.N_BITS+8), big.NewInt(1))
			t = new(big.Int).Add(new(big.Int).Lsh(t, zk.N_BITS+8), v)
			tt = new(big.Int).Add(new(big.Int).Lsh(tt, zk.N_BITS+8), vv)
		} else {
			y[i] = new(big.Int).Mod(t, N)
			t = new(big.Int).Div(t, N)
			tt = new(big.Int).Div(tt, N)
			i += 1
		}
	}

	// Step 3: Prove
	var wg sync.WaitGroup
	wg.Add(zk.T)
	x, z := [zk.T]*big.Int{}, [zk.T]*big.Int{}
	a, b := [zk.T]bool{}, [zk.T]bool{}
	p, q := witness.p, witness.q
	phi_N := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
	index := new(big.Int).ModInverse(N, phi_N)
	inv_p_mod_q, inv_q_mod_p := new(big.Int).ModInverse(p, q), new(big.Int).ModInverse(q, p)
	for i := 0; i < zk.T; i++ {
		go func (i int)  {
			z[i] = new(big.Int).Exp(y[i], index, N)
			for _, ab := range [][]bool{{false, false}, {false, true}, {true, false}, {true, true}} {
				y := y[i]
				if ab[0] {
					y = new(big.Int).Neg(y)
				}
				if ab[1] {
					y = new(big.Int).Mul(y, w)
				}
				y = new(big.Int).Mod(y, N)
				if big.Jacobi(y, p) == 1 && big.Jacobi(y, q) == 1 {
					// y has 4 square roots, i.e.,
					// (1) CRT(sqrt(y, p), sqrt(y, q))
					// (2) CRT(p - sqrt(y, p), sqrt(y, q))
					// (3) CRT(sqrt(y, p), q - sqrt(y, q))
					// (4) CRT(p - sqrt(y, p), q - sqrt(y, q))
					// But only (1) has its own square root
					y_sqrt := zk.CRT(new(big.Int).ModSqrt(y, p), new(big.Int).ModSqrt(y, q), p, q, inv_p_mod_q, inv_q_mod_p)
					x[i] = zk.CRT(new(big.Int).ModSqrt(y_sqrt, p), new(big.Int).ModSqrt(y_sqrt, q), p, q, inv_p_mod_q, inv_q_mod_p)
					a[i] = ab[0]
					b[i] = ab[1]
					break
				}
			}
			wg.Done()
		}(i)
	}

	wg.Wait()

	return &Proof{w, x, a, b, z}
}

func Verify(tx *merlin.Transcript, N *Statement, proof *Proof) bool {
	tx.AppendMessage([]byte("N"), N.Bytes()) // Strong Fiat-Shamir

	tx.AppendMessage([]byte("w"), proof.w.Bytes())

	// Step 2: Challenge (Fiat-Shamir)
	y := [zk.T]*big.Int{}
	t := big.NewInt(0)
	tt := big.NewInt(0)
	for i := 0; i < zk.T; {
		if tt.Cmp(N) == -1 {
			v := new(big.Int).SetBytes(tx.ExtractBytes([]byte(fmt.Sprintf("y[%d]", i)), zk.N_BITS/8+1))
			vv := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), zk.N_BITS+8), big.NewInt(1))
			t = new(big.Int).Add(new(big.Int).Lsh(t, zk.N_BITS+8), v)
			tt = new(big.Int).Add(new(big.Int).Lsh(tt, zk.N_BITS+8), vv)
		} else {
			y[i] = new(big.Int).Mod(t, N)
			t = new(big.Int).Div(t, N)
			tt = new(big.Int).Div(tt, N)
			i += 1
		}
	}

	// Step 4: Verify
	if N.ProbablyPrime(64) {
		return false
	}
	for i := 0; i < zk.T; i++ {
		if new(big.Int).Exp(proof.z[i], N, N).Cmp(y[i]) != 0 {
			return false
		}
		y := y[i]
		if proof.a[i] {
			y = new(big.Int).Neg(y)
		}
		if proof.b[i] {
			y = new(big.Int).Mul(y, proof.w)
		}
		y = new(big.Int).Mod(y, N)
		if new(big.Int).Exp(proof.x[i], big.NewInt(4), N).Cmp(y) != 0 {
			return false
		}
	}

	return true
}
