package zk_r_affran

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/paillier"
	"github.com/The9born/kryptology/pkg/tecdsa/2ecdsa/mta/paillier/zk"
	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"
)

func Test(t *testing.T) {
	q := curves.K256Curve().Params().N
	k := new(big.Int).Lsh(new(big.Int).Mul(q, q), zk.T+zk.L+zk.S)

	a, _ := rand.Int(rand.Reader, q)
	alpha, _ := rand.Int(rand.Reader, k)

	pk, _, _ := paillier.NewKeys()
	N := pk.N
	NN := pk.N2
	N_plus_1 := new(big.Int).Add(N, big.NewInt(1))
	c_B, _ := rand.Int(rand.Reader, q)
	c := zk.Commit(c_B, N_plus_1, big.NewInt(1), new(big.Int).Lsh(q, zk.T+zk.L), NN)
	c_A := zk.Commit(c, N_plus_1, a, alpha, NN)

	pk, _, _ = paillier.NewKeys()
	N0 := pk.N
	h_sqrt, _ := rand.Int(rand.Reader, N0)
	h := new(big.Int).Mod(new(big.Int).Mul(h_sqrt, h_sqrt), N0)
	u, _ := rand.Int(rand.Reader, N0)
	g := new(big.Int).Exp(h, u, N0)

	prover_tx := merlin.NewTranscript("test")
	verifier_tx := merlin.NewTranscript("test")

	pp := NewAgreed(q, N0, g, h, N, c_B)
	statement := c_A
	witness := NewWitness(a, alpha)

	proof := Prove(prover_tx, pp, witness, statement)
	require.True(t, Verify(verifier_tx, pp, statement, proof))
}

func BenchmarkProve(b *testing.B) {
	q := curves.K256Curve().Params().N
	k := new(big.Int).Lsh(new(big.Int).Mul(q, q), zk.T+zk.L+zk.S)

	a, _ := rand.Int(rand.Reader, q)
	alpha, _ := rand.Int(rand.Reader, k)

	pk, _, _ := paillier.NewKeys()
	N := pk.N
	NN := pk.N2
	N_plus_1 := new(big.Int).Add(N, big.NewInt(1))
	c_B, _ := rand.Int(rand.Reader, q)
	c := zk.Commit(c_B, N_plus_1, big.NewInt(1), new(big.Int).Lsh(q, zk.T+zk.L), NN)
	c_A := zk.Commit(c, N_plus_1, a, alpha, NN)

	pk, _, _ = paillier.NewKeys()
	N0 := pk.N
	h_sqrt, _ := rand.Int(rand.Reader, N0)
	h := new(big.Int).Mod(new(big.Int).Mul(h_sqrt, h_sqrt), N0)
	u, _ := rand.Int(rand.Reader, N0)
	g := new(big.Int).Exp(h, u, N0)

	prover_tx := merlin.NewTranscript("test")

	pp := NewAgreed(q, N0, g, h, N, c_B)
	statement := c_A
	witness := NewWitness(a, alpha)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Prove(prover_tx, pp, witness, statement)
	}
}

func BenchmarkVerify(b *testing.B) {
	q := curves.K256Curve().Params().N
	k := new(big.Int).Lsh(new(big.Int).Mul(q, q), zk.T+zk.L+zk.S)

	a, _ := rand.Int(rand.Reader, q)
	alpha, _ := rand.Int(rand.Reader, k)

	pk, _, _ := paillier.NewKeys()
	N := pk.N
	NN := pk.N2
	N_plus_1 := new(big.Int).Add(N, big.NewInt(1))
	c_B, _ := rand.Int(rand.Reader, q)
	c := zk.Commit(c_B, N_plus_1, big.NewInt(1), new(big.Int).Lsh(q, zk.T+zk.L), NN)
	c_A := zk.Commit(c, N_plus_1, a, alpha, NN)

	pk, _, _ = paillier.NewKeys()
	N0 := pk.N
	h_sqrt, _ := rand.Int(rand.Reader, N0)
	h := new(big.Int).Mod(new(big.Int).Mul(h_sqrt, h_sqrt), N0)
	u, _ := rand.Int(rand.Reader, N0)
	g := new(big.Int).Exp(h, u, N0)

	prover_tx := merlin.NewTranscript("test")
	verifier_tx := merlin.NewTranscript("test")

	pp := NewAgreed(q, N0, g, h, N, c_B)
	statement := c_A
	witness := NewWitness(a, alpha)

	proof := Prove(prover_tx, pp, witness, statement)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(verifier_tx, pp, statement, proof)
	}
}
