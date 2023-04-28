package sign_offline

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/coinbase/kryptology/pkg/ot/extension/kos"
	"github.com/coinbase/kryptology/pkg/ot/ottest"
	"github.com/coinbase/kryptology/pkg/paillier"
	"github.com/The9born/kryptology/pkg/tecdsa/2ecdsa/dkg"
	"github.com/The9born/kryptology/pkg/tecdsa/2ecdsa/mta/ot"
	"github.com/The9born/kryptology/pkg/tecdsa/2ecdsa/mta/paillier"
)

func TestOfflineOT(t *testing.T) {
	curve := curves.K256()

	alice := dkg.NewAlice(curve)
	bob := dkg.NewBob(curve)

	commitment, err := alice.Step1()
	require.NoError(t, err)
	bobProof, err := bob.Step2(commitment)
	require.NoError(t, err)
	aliceProof, err := alice.Step3(bobProof)
	require.NoError(t, err)
	err = bob.Step4(aliceProof)
	require.NoError(t, err)

	aliceView := alice.Output()
	bobView := bob.Output()

	require.Equal(t, aliceView.Pk, bobView.PkPeer)
	require.Equal(t, aliceView.PkPeer, bobView.Pk)
	require.Equal(t, aliceView.PkJoint, bobView.PkJoint)

	uniqueSessionId := [simplest.DigestSize]byte{}

	sender, _ := simplest.NewSender(curve, kos.Kappa, uniqueSessionId)
	receiver, _ := simplest.NewReceiver(curve, kos.Kappa, uniqueSessionId)
	r1, _ := sender.Round1ComputeAndZkpToPublicKey()
	r2, _ := receiver.Round2VerifySchnorrAndPadTransfer(r1)
	r3, _ := sender.Round3PadTransfer(r2)
	r4, _ := receiver.Round4RespondToChallenge(r3)
	r5, _ := sender.Round5Verify(r4)
	receiver.Round6Verify(r5)

	mta_sender, _ := mta_ot.NewSender(receiver.Output, curve, uniqueSessionId)
	mta_receiver, _ := mta_ot.NewReceiver(sender.Output, curve, uniqueSessionId)

	{
		alice := NewAlice[*mta_ot.Round1Output, *mta_ot.Round2Output](curve, aliceView, mta_sender)
		bob := NewBob[*mta_ot.Round1Output, *mta_ot.Round2Output](curve, bobView, mta_receiver)

		commitment, a := bob.Step1()
		q1, r1, cc, proof, b := alice.Step2(commitment, a)
		proof = bob.Step3(q1, r1, cc, proof, b)
		alice.Step4(proof)

		require.Equal(t, alice.Output().R, bob.Output().R)
	}
}

func BenchmarkOfflineOT(b *testing.B) {
	curve := curves.K256()

	alice := dkg.NewAlice(curve)
	bob := dkg.NewBob(curve)

	commitment, _ := alice.Step1()
	bobProof, _ := bob.Step2(commitment)
	aliceProof, _ := alice.Step3(bobProof)
	_ = bob.Step4(aliceProof)

	uniqueSessionId := [simplest.DigestSize]byte{}

	baseOtSenderOutput, baseOtReceiverOutput, _ := ottest.RunSimplestOT(curve, kos.Kappa, uniqueSessionId)

	mta_sender, _ := mta_ot.NewSender(baseOtReceiverOutput, curve, uniqueSessionId)
	mta_receiver, _ := mta_ot.NewReceiver(baseOtSenderOutput, curve, uniqueSessionId)

	{
		alice := NewAlice[*mta_ot.Round1Output, *mta_ot.Round2Output](curve, alice.Output(), mta_sender)
		bob := NewBob[*mta_ot.Round1Output, *mta_ot.Round2Output](curve, bob.Output(), mta_receiver)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			commitment, a := bob.Step1()
			q1, r1, cc, proof, b := alice.Step2(commitment, a)
			proof = bob.Step3(q1, r1, cc, proof, b)
			alice.Step4(proof)
		}
	}
}

func BenchmarkOfflineOTStep1(b *testing.B) {
	curve := curves.K256()

	alice := dkg.NewAlice(curve)
	bob := dkg.NewBob(curve)

	commitment, _ := alice.Step1()
	bobProof, _ := bob.Step2(commitment)
	aliceProof, _ := alice.Step3(bobProof)
	_ = bob.Step4(aliceProof)

	uniqueSessionId := [simplest.DigestSize]byte{}

	baseOtSenderOutput, _, _ := ottest.RunSimplestOT(curve, kos.Kappa, uniqueSessionId)

	mta_receiver, _ := mta_ot.NewReceiver(baseOtSenderOutput, curve, uniqueSessionId)

	{
		bob := NewBob[*mta_ot.Round1Output, *mta_ot.Round2Output](curve, bob.Output(), mta_receiver)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			bob.Step1()
		}
	}
}

func BenchmarkOfflineOTStep2(b *testing.B) {
	curve := curves.K256()

	alice := dkg.NewAlice(curve)
	bob := dkg.NewBob(curve)

	commitment, _ := alice.Step1()
	bobProof, _ := bob.Step2(commitment)
	aliceProof, _ := alice.Step3(bobProof)
	_ = bob.Step4(aliceProof)

	uniqueSessionId := [simplest.DigestSize]byte{}

	baseOtSenderOutput, baseOtReceiverOutput, _ := ottest.RunSimplestOT(curve, kos.Kappa, uniqueSessionId)

	mta_sender, _ := mta_ot.NewSender(baseOtReceiverOutput, curve, uniqueSessionId)
	mta_receiver, _ := mta_ot.NewReceiver(baseOtSenderOutput, curve, uniqueSessionId)

	{
		alice := NewAlice[*mta_ot.Round1Output, *mta_ot.Round2Output](curve, alice.Output(), mta_sender)
		bob := NewBob[*mta_ot.Round1Output, *mta_ot.Round2Output](curve, bob.Output(), mta_receiver)
		commitment, a := bob.Step1()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			alice.Step2(commitment, a)
		}
	}
}

func BenchmarkOfflineOTStep3(b *testing.B) {
	curve := curves.K256()

	alice := dkg.NewAlice(curve)
	bob := dkg.NewBob(curve)

	commitment, _ := alice.Step1()
	bobProof, _ := bob.Step2(commitment)
	aliceProof, _ := alice.Step3(bobProof)
	_ = bob.Step4(aliceProof)

	uniqueSessionId := [simplest.DigestSize]byte{}

	baseOtSenderOutput, baseOtReceiverOutput, _ := ottest.RunSimplestOT(curve, kos.Kappa, uniqueSessionId)

	mta_sender, _ := mta_ot.NewSender(baseOtReceiverOutput, curve, uniqueSessionId)
	mta_receiver, _ := mta_ot.NewReceiver(baseOtSenderOutput, curve, uniqueSessionId)

	{
		alice := NewAlice[*mta_ot.Round1Output, *mta_ot.Round2Output](curve, alice.Output(), mta_sender)
		bob := NewBob[*mta_ot.Round1Output, *mta_ot.Round2Output](curve, bob.Output(), mta_receiver)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			commitment, a := bob.Step1()
			q1, r1, cc, proof, bb := alice.Step2(commitment, a)
			b.StartTimer()
			proof = bob.Step3(q1, r1, cc, proof, bb)
			b.StopTimer()
			alice.Step4(proof)
		}
	}
}

func BenchmarkOfflineOTStep4(b *testing.B) {
	curve := curves.K256()

	alice := dkg.NewAlice(curve)
	bob := dkg.NewBob(curve)

	commitment, _ := alice.Step1()
	bobProof, _ := bob.Step2(commitment)
	aliceProof, _ := alice.Step3(bobProof)
	_ = bob.Step4(aliceProof)

	uniqueSessionId := [simplest.DigestSize]byte{}

	baseOtSenderOutput, baseOtReceiverOutput, _ := ottest.RunSimplestOT(curve, kos.Kappa, uniqueSessionId)

	mta_sender, _ := mta_ot.NewSender(baseOtReceiverOutput, curve, uniqueSessionId)
	mta_receiver, _ := mta_ot.NewReceiver(baseOtSenderOutput, curve, uniqueSessionId)

	{
		alice := NewAlice[*mta_ot.Round1Output, *mta_ot.Round2Output](curve, alice.Output(), mta_sender)
		bob := NewBob[*mta_ot.Round1Output, *mta_ot.Round2Output](curve, bob.Output(), mta_receiver)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			commitment, a := bob.Step1()
			q1, r1, cc, proof, bb := alice.Step2(commitment, a)
			proof = bob.Step3(q1, r1, cc, proof, bb)
			b.StartTimer()
			alice.Step4(proof)
		}
	}
}

var p, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
var q, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
var p0, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
var q0, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)

func TestOfflinePaillier(t *testing.T) {
	curve := curves.K256()

	alice := dkg.NewAlice(curve)
	bob := dkg.NewBob(curve)

	commitment, err := alice.Step1()
	require.NoError(t, err)
	bobProof, err := bob.Step2(commitment)
	require.NoError(t, err)
	aliceProof, err := alice.Step3(bobProof)
	require.NoError(t, err)
	err = bob.Step4(aliceProof)
	require.NoError(t, err)

	aliceView := alice.Output()
	bobView := bob.Output()

	require.Equal(t, aliceView.Pk, bobView.PkPeer)
	require.Equal(t, aliceView.PkPeer, bobView.Pk)
	require.Equal(t, aliceView.PkJoint, bobView.PkJoint)

	sender := mta_paillier.NewSender(curve, p, q)
	receiver := mta_paillier.NewReceiver(curve, p0, q0)

	setup1Statement, setup1Proof := receiver.SetupInit()
	setup2Statement, setup2Proof := sender.SetupUpdate(setup1Statement, setup1Proof)
	receiver.SetupDone(setup2Statement, setup2Proof)

	{
		alice := NewAlice[*mta_paillier.Round1Output, *mta_paillier.Round2Output](curve, aliceView, sender)
		bob := NewBob[*mta_paillier.Round1Output, *mta_paillier.Round2Output](curve, bobView, receiver)

		commitment, a := bob.Step1()
		q1, r1, cc, proof, b := alice.Step2(commitment, a)
		proof = bob.Step3(q1, r1, cc, proof, b)
		alice.Step4(proof)

		require.Equal(t, alice.Output().R, bob.Output().R)
	}
}

func BenchmarkOfflinePaillier(b *testing.B) {
	curve := curves.K256()

	alice := dkg.NewAlice(curve)
	bob := dkg.NewBob(curve)

	commitment, _ := alice.Step1()
	bobProof, _ := bob.Step2(commitment)
	aliceProof, _ := alice.Step3(bobProof)
	_ = bob.Step4(aliceProof)

	aliceView := alice.Output()
	bobView := bob.Output()

	sender := mta_paillier.NewSender(curve, p, q)
	receiver := mta_paillier.NewReceiver(curve, p0, q0)

	setup1Statement, setup1Proof := receiver.SetupInit()
	setup2Statement, setup2Proof := sender.SetupUpdate(setup1Statement, setup1Proof)
	receiver.SetupDone(setup2Statement, setup2Proof)

	{
		alice := NewAlice[*mta_paillier.Round1Output, *mta_paillier.Round2Output](curve, aliceView, sender)
		bob := NewBob[*mta_paillier.Round1Output, *mta_paillier.Round2Output](curve, bobView, receiver)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			commitment, a := bob.Step1()
			q1, r1, cc, proof, b := alice.Step2(commitment, a)
			proof = bob.Step3(q1, r1, cc, proof, b)
			alice.Step4(proof)
		}
	}
}

func BenchmarkOfflinePaillierStep1(b *testing.B) {
	curve := curves.K256()

	alice := dkg.NewAlice(curve)
	bob := dkg.NewBob(curve)

	commitment, _ := alice.Step1()
	bobProof, _ := bob.Step2(commitment)
	aliceProof, _ := alice.Step3(bobProof)
	_ = bob.Step4(aliceProof)

	bobView := bob.Output()

	sender := mta_paillier.NewSender(curve, p, q)
	receiver := mta_paillier.NewReceiver(curve, p0, q0)

	setup1Statement, setup1Proof := receiver.SetupInit()
	setup2Statement, setup2Proof := sender.SetupUpdate(setup1Statement, setup1Proof)
	receiver.SetupDone(setup2Statement, setup2Proof)

	{
		bob := NewBob[*mta_paillier.Round1Output, *mta_paillier.Round2Output](curve, bobView, receiver)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			bob.Step1()
		}
	}
}

func BenchmarkOfflinePaillierStep2(b *testing.B) {
	curve := curves.K256()

	alice := dkg.NewAlice(curve)
	bob := dkg.NewBob(curve)

	commitment, _ := alice.Step1()
	bobProof, _ := bob.Step2(commitment)
	aliceProof, _ := alice.Step3(bobProof)
	_ = bob.Step4(aliceProof)

	aliceView := alice.Output()
	bobView := bob.Output()

	sender := mta_paillier.NewSender(curve, p, q)
	receiver := mta_paillier.NewReceiver(curve, p0, q0)

	setup1Statement, setup1Proof := receiver.SetupInit()
	setup2Statement, setup2Proof := sender.SetupUpdate(setup1Statement, setup1Proof)
	receiver.SetupDone(setup2Statement, setup2Proof)

	{
		alice := NewAlice[*mta_paillier.Round1Output, *mta_paillier.Round2Output](curve, aliceView, sender)
		bob := NewBob[*mta_paillier.Round1Output, *mta_paillier.Round2Output](curve, bobView, receiver)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			commitment, a := bob.Step1()
			b.StartTimer()
			q1, r1, cc, proof, bb := alice.Step2(commitment, a)
			b.StopTimer()
			proof = bob.Step3(q1, r1, cc, proof, bb)
			alice.Step4(proof)
		}
	}
}

func BenchmarkOfflinePaillierStep3(b *testing.B) {
	curve := curves.K256()

	alice := dkg.NewAlice(curve)
	bob := dkg.NewBob(curve)

	commitment, _ := alice.Step1()
	bobProof, _ := bob.Step2(commitment)
	aliceProof, _ := alice.Step3(bobProof)
	_ = bob.Step4(aliceProof)

	aliceView := alice.Output()
	bobView := bob.Output()

	sender := mta_paillier.NewSender(curve, p, q)
	receiver := mta_paillier.NewReceiver(curve, p0, q0)

	setup1Statement, setup1Proof := receiver.SetupInit()
	setup2Statement, setup2Proof := sender.SetupUpdate(setup1Statement, setup1Proof)
	receiver.SetupDone(setup2Statement, setup2Proof)

	{
		alice := NewAlice[*mta_paillier.Round1Output, *mta_paillier.Round2Output](curve, aliceView, sender)
		bob := NewBob[*mta_paillier.Round1Output, *mta_paillier.Round2Output](curve, bobView, receiver)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			commitment, a := bob.Step1()
			q1, r1, cc, proof, bb := alice.Step2(commitment, a)
			b.StartTimer()
			proof = bob.Step3(q1, r1, cc, proof, bb)
			b.StopTimer()
			alice.Step4(proof)
		}
	}
}

func BenchmarkOfflinePaillierStep4(b *testing.B) {
	curve := curves.K256()

	alice := dkg.NewAlice(curve)
	bob := dkg.NewBob(curve)

	commitment, _ := alice.Step1()
	bobProof, _ := bob.Step2(commitment)
	aliceProof, _ := alice.Step3(bobProof)
	_ = bob.Step4(aliceProof)

	aliceView := alice.Output()
	bobView := bob.Output()

	sender := mta_paillier.NewSender(curve, p, q)
	receiver := mta_paillier.NewReceiver(curve, p0, q0)

	setup1Statement, setup1Proof := receiver.SetupInit()
	setup2Statement, setup2Proof := sender.SetupUpdate(setup1Statement, setup1Proof)
	receiver.SetupDone(setup2Statement, setup2Proof)

	{
		alice := NewAlice[*mta_paillier.Round1Output, *mta_paillier.Round2Output](curve, aliceView, sender)
		bob := NewBob[*mta_paillier.Round1Output, *mta_paillier.Round2Output](curve, bobView, receiver)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			commitment, a := bob.Step1()
			q1, r1, cc, proof, bb := alice.Step2(commitment, a)
			proof = bob.Step3(q1, r1, cc, proof, bb)
			b.StartTimer()
			alice.Step4(proof)
		}
	}
}
