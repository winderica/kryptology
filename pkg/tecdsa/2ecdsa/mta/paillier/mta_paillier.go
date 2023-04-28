package mta_paillier

import (
	"crypto/rand"
	"math/big"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/paillier"
	"github.com/The9born/kryptology/pkg/tecdsa/2ecdsa/mta/paillier/zk"
	"github.com/The9born/kryptology/pkg/tecdsa/2ecdsa/mta/paillier/zk/qr"
	"github.com/The9born/kryptology/pkg/tecdsa/2ecdsa/mta/paillier/zk/qrdl"
	"github.com/The9born/kryptology/pkg/tecdsa/2ecdsa/mta/paillier/zk/r_affran"
	"github.com/The9born/kryptology/pkg/tecdsa/2ecdsa/mta/paillier/zk/r_p"
	"github.com/The9born/kryptology/pkg/tecdsa/2ecdsa/mta/paillier/zk/r_pwr"
	"github.com/gtank/merlin"
)

type Param struct {
	q  *big.Int
	N0 *big.Int
	g0 *big.Int
	h0 *big.Int
	N  *big.Int
	g  *big.Int
	h  *big.Int
}

type Sender struct {
	tx    *merlin.Transcript
	pp    *Param
	curve *curves.Curve
	p *big.Int
	q *big.Int
	sk    *paillier.SecretKey
}

type Receiver struct {
	tx    *merlin.Transcript
	pp    *Param
	curve *curves.Curve
	p *big.Int
	q *big.Int
	sk    *paillier.SecretKey
	c_B   *big.Int
}

type SetupStatement struct {
	r_p  *zk_r_p.Statement
	qr   *zk_qr.Statement
	qrdl *zk_qrdl.Statement
}

type SetupProof struct {
	r_p  *zk_r_p.Proof
	qr   *zk_qr.Proof
	qrdl *zk_qrdl.Proof
}

type Round1Output struct {
	c_B   *zk_r_pwr.Statement
	proof *zk_r_pwr.Proof
}

type Round2Output struct {
	c_A   *zk_r_affran.Statement
	proof *zk_r_affran.Proof
}

func NewSender(curve *curves.Curve, p *big.Int, q *big.Int) *Sender {
	c, _ := curve.ToEllipticCurve()
	sk, _ := paillier.NewSecretKey(p, q)
	return &Sender{
		tx: merlin.NewTranscript("MTA-Paillier"),
		pp: &Param{
			q: c.Params().N,
		},
		curve: curve,
		p: p,
		q: q,
		sk: sk,
	}
}

func NewReceiver(curve *curves.Curve, p *big.Int, q *big.Int) *Receiver {
	c, _ := curve.ToEllipticCurve()
	sk, _ := paillier.NewSecretKey(p, q)
	return &Receiver{
		tx: merlin.NewTranscript("MTA-Paillier"),
		pp: &Param{
			q: c.Params().N,
		},
		curve: curve,
		p: p,
		q: q,
		sk: sk,
	}
}

func (receiver *Receiver) SetupInit() (SetupStatement, SetupProof) {
	// P2 generates N, g, h
	receiver.pp.N = receiver.sk.N
	h_sqrt, _ := rand.Int(rand.Reader, receiver.pp.N)
	receiver.pp.h = new(big.Int).Mod(new(big.Int).Mul(h_sqrt, h_sqrt), receiver.pp.N)
	alpha, _ := rand.Int(rand.Reader, receiver.pp.N)
	receiver.pp.g = new(big.Int).Exp(receiver.pp.h, alpha, receiver.pp.N)

	// P2 computes the corresponding proofs
	input_r_p := receiver.pp.N
	pi_r_p := zk_r_p.Prove(receiver.tx, zk_r_p.NewWitness(receiver.p, receiver.q), input_r_p)
	input_qr := receiver.pp.h
	pi_qr := zk_qr.Prove(receiver.tx, zk_qr.NewAgreed(receiver.pp.N), zk_qr.NewWitness(h_sqrt), input_qr)
	input_qrdl := receiver.pp.g
	pi_qrdl := zk_qrdl.Prove(receiver.tx, zk_qrdl.NewAgreed(receiver.pp.N, receiver.pp.h), zk_qrdl.NewWitness(alpha), input_qrdl)

	return SetupStatement{input_r_p, input_qr, input_qrdl}, SetupProof{pi_r_p, pi_qr, pi_qrdl}
}

func (sender *Sender) SetupUpdate(statement SetupStatement, proof SetupProof) (SetupStatement, SetupProof) {
	// P1 ensures N, g, h are valid
	if !zk_r_p.Verify(sender.tx, statement.r_p, proof.r_p) {
		panic("MtA SetupUpdate: R_P")
	}
	sender.pp.N = statement.r_p
	if !zk_qr.Verify(sender.tx, zk_qr.NewAgreed(sender.pp.N), statement.qr, proof.qr) {
		panic("MtA SetupUpdate: QR")
	}
	sender.pp.h = statement.qr
	if !zk_qrdl.Verify(sender.tx, zk_qrdl.NewAgreed(sender.pp.N, sender.pp.h), statement.qrdl, proof.qrdl) {
		panic("MtA SetupUpdate: QRdl")
	}
	sender.pp.g = statement.qrdl

	// P1 generates N0, g0, h0
	sender.pp.N0 = sender.sk.N
	h0_sqrt, _ := rand.Int(rand.Reader, sender.pp.N0)
	sender.pp.h0 = new(big.Int).Mod(new(big.Int).Mul(h0_sqrt, h0_sqrt), sender.pp.N0)
	alpha0, _ := rand.Int(rand.Reader, sender.pp.N0)
	sender.pp.g0 = new(big.Int).Exp(sender.pp.h0, alpha0, sender.pp.N0)

	// P1 computes the corresponding proofs
	input_r_p := sender.pp.N0
	pi_r_p := zk_r_p.Prove(sender.tx, zk_r_p.NewWitness(sender.p, sender.q), input_r_p)
	input_qr := sender.pp.h0
	pi_qr := zk_qr.Prove(sender.tx, zk_qr.NewAgreed(sender.pp.N0), zk_qr.NewWitness(h0_sqrt), input_qr)
	input_qrdl := sender.pp.g0
	pi_qrdl := zk_qrdl.Prove(sender.tx, zk_qrdl.NewAgreed(sender.pp.N0, sender.pp.h0), zk_qrdl.NewWitness(alpha0), input_qrdl)

	return SetupStatement{input_r_p, input_qr, input_qrdl}, SetupProof{pi_r_p, pi_qr, pi_qrdl}
}

func (receiver *Receiver) SetupDone(statement SetupStatement, proof SetupProof) {
	// P2 ensures N0, g0, h0 are valid
	if !zk_r_p.Verify(receiver.tx, statement.r_p, proof.r_p) {
		panic("MtA SetupDone: R_P")
	}
	receiver.pp.N0 = statement.r_p
	if !zk_qr.Verify(receiver.tx, zk_qr.NewAgreed(receiver.pp.N0), statement.qr, proof.qr) {
		panic("MtA SetupDone: QR")
	}
	receiver.pp.h0 = statement.qr
	if !zk_qrdl.Verify(receiver.tx, zk_qrdl.NewAgreed(receiver.pp.N0, receiver.pp.h0), statement.qrdl, proof.qrdl) {
		panic("MtA SetupDone: QRdl")
	}
	receiver.pp.g0 = statement.qrdl
}

func (receiver *Receiver) Init(b curves.Scalar) *Round1Output {
	pp_r_pwr := zk_r_pwr.NewAgreed(receiver.pp.q, receiver.pp.N0, receiver.pp.g0, receiver.pp.h0, receiver.pp.N)

	r, _ := rand.Int(rand.Reader, receiver.pp.N)
	receiver.c_B = zk.Commit(r, pp_r_pwr.N_plus_1, receiver.pp.N, b.BigInt(), pp_r_pwr.NN)

	input_r_pwr := receiver.c_B
	pi_r_pwr := zk_r_pwr.Prove(receiver.tx, pp_r_pwr, zk_r_pwr.NewWitness(b.BigInt(), r), receiver.c_B)

	return &Round1Output{input_r_pwr, pi_r_pwr}
}

func (sender *Sender) Update(a curves.Scalar, round1Output *Round1Output) (curves.Scalar, *Round2Output) {
	pp_r_pwr := zk_r_pwr.NewAgreed(sender.pp.q, sender.pp.N0, sender.pp.g0, sender.pp.h0, sender.pp.N)

	if !zk_r_pwr.Verify(sender.tx, pp_r_pwr, round1Output.c_B, round1Output.proof) {
		panic("MtA Update: R_PwR")
	}

	pp_r_affran := zk_r_affran.NewAgreed(sender.pp.q, sender.pp.N, sender.pp.g, sender.pp.h, sender.pp.N, round1Output.c_B)

	alpha_prime, _ := rand.Int(rand.Reader, pp_r_affran.K)
	alpha, _ := sender.curve.Scalar.SetBigInt(new(big.Int).Mod(alpha_prime, sender.pp.q))
	alpha = alpha.Neg()

	c := zk.Commit(round1Output.c_B, pp_r_pwr.N_plus_1, big.NewInt(1), new(big.Int).Lsh(sender.pp.q, zk.T+zk.L), pp_r_pwr.NN)
	c_A := zk.Commit(c, pp_r_pwr.N_plus_1, a.BigInt(), alpha_prime, pp_r_pwr.NN)

	input_r_affran := c_A
	pi_r_affran := zk_r_affran.Prove(sender.tx, pp_r_affran, zk_r_affran.NewWitness(a.BigInt(), alpha_prime), input_r_affran)

	return alpha, &Round2Output{input_r_affran, pi_r_affran}
}

func (receiver *Receiver) Multiply(round2Output *Round2Output) curves.Scalar {
	pp_r_affran := zk_r_affran.NewAgreed(receiver.pp.q, receiver.pp.N, receiver.pp.g, receiver.pp.h, receiver.pp.N, receiver.c_B)

	if !zk_r_affran.Verify(receiver.tx, pp_r_affran, round2Output.c_A, round2Output.proof) {
		panic("MtA Multiply: R_AffRan")
	}

	beta_prime, _ := receiver.sk.Decrypt(round2Output.c_A)
	beta, _ := receiver.curve.Scalar.SetBigInt(new(big.Int).Mod(beta_prime, receiver.pp.q))

	return beta
}
