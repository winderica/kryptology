package sign_offline

import (
	"crypto/rand"
	"math/big"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/The9born/kryptology/pkg/tecdsa/2ecdsa/dkg"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
)

type MTAReceiver[A any, B any] interface {
	Init(curves.Scalar) A
	Multiply(B) curves.Scalar
}

type MTASender[A any, B any] interface {
	Update(curves.Scalar, A) (curves.Scalar, B)
}

type Alice[A any, B any] struct {
	r             curves.Scalar
	bobCommitment schnorr.Commitment
	k1            curves.Scalar
	x1            curves.Scalar
	r1            curves.Scalar
	prover        *schnorr.Prover
	curve         *curves.Curve
	sk            curves.Scalar
	pk            curves.Point
	pkPeer        curves.Point
	pkJoint       curves.Point
	sender        MTASender[A, B]
}

type Bob[A any, B any] struct {
	r        curves.Scalar
	k2       curves.Scalar
	x2       curves.Scalar
	r1       curves.Scalar
	prover   *schnorr.Prover
	proof    *schnorr.Proof
	curve    *curves.Curve
	sk       curves.Scalar
	pk       curves.Point
	pkPeer   curves.Point
	pkJoint  curves.Point
	receiver MTAReceiver[A, B]
}

type AliceOutput struct {
	R  curves.Scalar
	X1 curves.Scalar
	K1 curves.Scalar
	PkJoint curves.Point
}

type BobOutput struct {
	R  curves.Scalar
	K2 curves.Scalar
	X2 curves.Scalar
	R1 curves.Scalar
	PkJoint curves.Point
}

// NewAlice creates a party that can participate in protocol runs of DKLs sign, in the role of Alice.
func NewAlice[A any, B any](curve *curves.Curve, output *dkg.Output, sender MTASender[A, B]) *Alice[A, B] {
	return &Alice[A, B]{
		sk:      output.Sk,
		pk:      output.Pk,
		pkPeer:  output.PkPeer,
		pkJoint: output.PkJoint,
		curve:   curve,
		sender:  sender,
	}
}

// NewBob creates a party that can participate in protocol runs of DKLs sign, in the role of Bob.
// This party receives the signature at the end.
func NewBob[A any, B any](curve *curves.Curve, output *dkg.Output, receiver MTAReceiver[A, B]) *Bob[A, B] {
	return &Bob[A, B]{
		sk:       output.Sk,
		pk:       output.Pk,
		pkPeer:   output.PkPeer,
		pkJoint:  output.PkJoint,
		curve:    curve,
		receiver: receiver,
	}
}

func (bob *Bob[A, B]) Step1() (schnorr.Commitment, A) {
	bob.k2 = bob.curve.Scalar.Random(rand.Reader)

	uniqueSessionId := [simplest.DigestSize]byte{}
	bob.prover = schnorr.NewProver(bob.curve, nil, uniqueSessionId[:])
	proof, commitment, err := bob.prover.ProveCommit(bob.k2)
	if err != nil {
		panic("step 1")
	}
	bob.proof = proof
	return commitment, bob.receiver.Init(bob.k2)
}

func (alice *Alice[A, B]) Step2(commitment schnorr.Commitment, a A) (curves.Point, curves.Scalar, curves.Scalar, *schnorr.Proof, B) {
	alice.x1 = alice.curve.Scalar.Random(rand.Reader)
	alice.k1 = alice.curve.Scalar.Random(rand.Reader)
	alice.bobCommitment = commitment

	uniqueSessionId := [simplest.DigestSize]byte{}
	alice.prover = schnorr.NewProver(alice.curve, nil, uniqueSessionId[:])

	proof, err := alice.prover.Prove(alice.k1)

	if err != nil {
		panic("step 2")
	}

	q1 := alice.curve.ScalarBaseMult(alice.x1)

	ta, b := alice.sender.Update(alice.x1, a)

	alice.r1 = alice.curve.Scalar.Random(rand.Reader)
	cc := alice.r1.Mul(alice.x1).Add(ta).Sub(alice.sk)

	return q1, alice.r1, cc, proof, b
}

func (bob *Bob[A, B]) Step3(q1 curves.Point, r1 curves.Scalar, cc curves.Scalar, proof *schnorr.Proof, b B) *schnorr.Proof {
	tb := bob.receiver.Multiply(b)

	if !bob.curve.ScalarBaseMult(tb.Add(cc)).Equal(q1.Mul(r1.Add(bob.k2)).Sub(bob.pkPeer)) {
		panic("step 3")
	}

	bob.r1 = r1

	uniqueSessionId := [simplest.DigestSize]byte{}

	err := schnorr.Verify(proof, bob.curve, nil, uniqueSessionId[:])
	if err != nil {
		panic("step 3")
	}

	r := proof.Statement.Mul(bob.k2.Add(bob.r1)).ToAffineUncompressed()

	bob.r, err = bob.curve.Scalar.SetBigInt(new(big.Int).SetBytes(r[1:1 + (len(r) >> 1)]))

	if err != nil {
		panic("step 3")
	}

	bob.x2 = bob.sk.Sub(tb.Add(cc))

	return bob.proof
}

func (alice *Alice[A, B]) Step4(proof *schnorr.Proof) {
	uniqueSessionId := [simplest.DigestSize]byte{}

	err := schnorr.DecommitVerify(proof, alice.bobCommitment, alice.curve, nil, uniqueSessionId[:])
	if err != nil {
		panic("step 4")
	}

	r := proof.Statement.Add(alice.curve.ScalarBaseMult(alice.r1)).Mul(alice.k1).ToAffineUncompressed()

	alice.r, err = alice.curve.Scalar.SetBigInt(new(big.Int).SetBytes(r[1:1 + (len(r) >> 1)]))

	if err != nil {
		panic("step 4")
	}
}

func (alice *Alice[A, B]) Output() *AliceOutput {
	return &AliceOutput{
		R:  alice.r,
		X1: alice.x1,
		K1: alice.k1,
		PkJoint: alice.pkJoint,
	}
}

func (bob *Bob[A, B]) Output() *BobOutput {
	return &BobOutput{
		R:  bob.r,
		K2: bob.k2,
		X2: bob.x2,
		R1: bob.r1,
		PkJoint: bob.pkJoint,
	}
}
