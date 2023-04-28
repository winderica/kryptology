package sign_online

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/The9born/kryptology/pkg/tecdsa/2ecdsa/sign_offline"
)

// Alice struct encoding Alice's state during one execution of the overall signing algorithm.
// At the end of the joint computation, Alice will not possess the signature.
type Alice struct {
	curve *curves.Curve
	r     curves.Scalar
	x1    curves.Scalar
	k1    curves.Scalar
	pkJoint curves.Point
}

// Bob struct encoding Bob's state during one execution of the overall signing algorithm.
// At the end of the joint computation, Bob will obtain the signature.
type Bob struct {
	curve *curves.Curve
	r     curves.Scalar
	k2    curves.Scalar
	x2    curves.Scalar
	r1    curves.Scalar
}

// NewAlice creates a party that can participate in protocol runs of DKLs sign, in the role of Alice.
func NewAlice(curve *curves.Curve, output *sign_offline.AliceOutput) *Alice {
	return &Alice{
		curve: curve,
		r:     output.R,
		x1:    output.X1,
		k1:    output.K1,
		pkJoint: output.PkJoint,
	}
}

// NewBob creates a party that can participate in protocol runs of DKLs sign, in the role of Bob.
// This party receives the signature at the end.
func NewBob(curve *curves.Curve, output *sign_offline.BobOutput) *Bob {
	return &Bob{
		curve: curve,
		r:     output.R,
		k2:    output.K2,
		x2:    output.X2,
		r1:    output.R1,
	}
}

func (bob *Bob) Step1(m []byte) curves.Scalar {
	h := bob.curve.Scalar.Hash(m)

	s2 := bob.r.MulAdd(bob.x2, h).Div(bob.k2.Add(bob.r1))

	return s2
}

func (alice *Alice) Step2(m []byte, s2 curves.Scalar) *curves.EcdsaSignature {
	s := alice.r.MulAdd(alice.x1, s2).Div(alice.k1).BigInt()
	r := alice.r.BigInt()

	curve, _ := alice.curve.ToEllipticCurve()
	pk := alice.pkJoint.ToAffineUncompressed()
	x := new(big.Int).SetBytes(pk[1:1 + (len(pk) >> 1)])
	y := new(big.Int).SetBytes(pk[1 + (len(pk) >> 1):])
	h := alice.curve.Scalar.Hash(m).Bytes()

	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: curve, X: x, Y: y}, h, r, s) {
		panic("verify")
	}

	return &curves.EcdsaSignature{
		V: 0,
		S: s,
		R: r,
	}
}
