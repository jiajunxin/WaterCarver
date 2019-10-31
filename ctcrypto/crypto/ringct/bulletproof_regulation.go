package ringct

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/ctcrypto/crypto"
)

func GenRegulationParaForBulletproof() (sL, sR *[64]crypto.Key, rho *crypto.Key, S *crypto.Key) {
	var sLTemp, sRTemp [64]crypto.Key
	var STemp crypto.Key
	for i := range sL {
		sLTemp[i] = crypto.SkGen()
		sRTemp[i] = crypto.SkGen()
	}
	sL = &sLTemp
	sR = &sRTemp
	rhoTemp := crypto.SkGen()
	rho = &rhoTemp
	ve := vector_exponent(sL[:], sR[:])
	rho_base_tmp := crypto.ScalarmultBase(*rho)
	crypto.AddKeys(&STemp, &ve, &rho_base_tmp)
	S = &STemp
	return
}

func GenRegulationParaForBulletproof2(num uint32) (sL, sR []crypto.Key, rho *crypto.Key, S *crypto.Key) {
	var M, logM int
	for {
		M = 1 << uint(logM)
		if M <= maxM && M < int(num) {
			logM++
		} else {
			break
		}
	}
	vlen := M * 64
	sLTemp := make([]crypto.Key, vlen)
	sRTemp := make([]crypto.Key, vlen)
	var STemp crypto.Key
	for i := range sLTemp {
		sLTemp[i] = crypto.SkGen()
		sRTemp[i] = crypto.SkGen()
	}
	sL = sLTemp
	sR = sRTemp
	rhoTemp := crypto.SkGen()
	rho = &rhoTemp
	ve := vector_exponent(sL[:], sR[:])
	rho_base_tmp := crypto.ScalarmultBase(*rho)
	crypto.AddKeys(&STemp, &ve, &rho_base_tmp)
	S = &STemp
	return
}

//ProveRangeBulletproofWithRegulation is a bulletproof with regulation
func ProveRangeBulletproofWithRegulation(C *crypto.Key, mask *crypto.Key, amount uint64, sL, sR *[64]crypto.Key, rho *crypto.Key) BulletProof {
	tmpmask := crypto.SkGen()
	copy(mask[:], tmpmask[:])
	proof := BULLETPROOF_Prove_Amount_WithRegulation(amount, mask, sL, sR, rho)
	if len(proof.V) != 1 {
		panic(fmt.Sprintf("V has not exactly one element"))
	}
	copy(C[:], proof.V[0][:]) //C = proof.V[0];
	return *proof
}

//BULLETPROOF_Prove_Amount_WithRegulation proves an amount with regulation
func BULLETPROOF_Prove_Amount_WithRegulation(v uint64, gamma *crypto.Key, sL, sR *[64]crypto.Key, rho *crypto.Key) *BulletProof {
	sv := crypto.Zero

	sv[0] = byte(v & 255)
	sv[1] = byte((v >> 8) & 255)
	sv[2] = byte((v >> 16) & 255)
	sv[3] = byte((v >> 24) & 255)
	sv[4] = byte((v >> 32) & 255)
	sv[5] = byte((v >> 40) & 255)
	sv[6] = byte((v >> 48) & 255)
	sv[7] = byte((v >> 56) & 255)

	return BULLETPROOF_Prove_WithRegulation(&sv, gamma, sL, sR, rho)
}

//BULLETPROOF_Prove_WithRegulation : Given a value v (0..2^N-1) and a mask gamma, construct a range proof
func BULLETPROOF_Prove_WithRegulation(sv *crypto.Key, gamma *crypto.Key, sL, sR *[64]crypto.Key, rho *crypto.Key) *BulletProof {
	const logN = int(6) // log2(64)
	const N = int(64)   // 1 << logN

	var V crypto.Key
	var aL, aR [N]crypto.Key
	var A, S crypto.Key

	// prove V
	crypto.AddKeys2(&V, gamma, sv, &crypto.H)

	// prove aL,aR
	// the entire amount in uint64 is extracted into bits and
	// different action taken if bit is zero or bit is one
	for i := N - 1; i >= 0; i-- {
		if (sv[i/8] & (1 << (uint64(i) % 8))) >= 1 {
			aL[i] = crypto.Identity
		} else {
			aL[i] = crypto.Zero
		}
		crypto.ScSub(&aR[i], &aL[i], &crypto.Identity)
	}

	hashcache := *(crypto.HashToScalar(V[:]))

	// prove STEP 1

	// PAPER LINES 38-39
	alpha := crypto.SkGen()
	ve := vector_exponent(aL[:], aR[:])

	alpha_base_tmp := crypto.ScalarmultBase(alpha)
	crypto.AddKeys(&A, &ve, &alpha_base_tmp)

	// PAPER LINES 40-42
	// var sL, sR [N]crypto.Key
	// for i := range sL {
	// 	sL[i] = crypto.SkGen()
	// 	sR[i] = crypto.SkGen()
	// }
	// //rct::keyV sL = rct::skvGen(N), sR = rct::skvGen(N);
	// rho := crypto.SkGen()
	ve = vector_exponent(sL[:], sR[:])
	rho_base_tmp := crypto.ScalarmultBase(*rho)
	crypto.AddKeys(&S, &ve, &rho_base_tmp)

	// PAPER LINES 43-45
	y := hash_cache_mash2(&hashcache, A, S)  //   rct::key y = hash_cache_mash(hash_cache, A, S);
	hashcache = *(crypto.HashToScalar(y[:])) // rct::key z = hash_cache = rct::hash_to_scalar(y);
	z := hashcache

	// Polynomial construction before PAPER LINE 46
	t0 := crypto.Zero // rct::key t0 = rct::zero();
	t1 := crypto.Zero // rct::key t1 = rct::zero();
	t2 := crypto.Zero // rct::key t2 = rct::zero();

	yN := vector_powers(y, int64(N)) // const auto yN = vector_powers(y, N);

	ip1y := inner_product(oneN, yN)      //rct::key ip1y = inner_product(oneN, yN);
	crypto.ScMulAdd(&t0, &z, &ip1y, &t0) // sc_muladd(t0.bytes, z.bytes, ip1y.bytes, t0.bytes);

	var zsq crypto.Key                  //rct::key zsq;
	crypto.ScMul(&zsq, &z, &z)          // sc_mul(zsq.bytes, z.bytes, z.bytes);
	crypto.ScMulAdd(&t0, &zsq, sv, &t0) // sc_muladd(t0.bytes, zsq.bytes, sv.bytes, t0.bytes);

	k := crypto.Zero                     // rct::key k = rct::zero();
	crypto.ScMulSub(&k, &zsq, &ip1y, &k) //sc_mulsub(k.bytes, zsq.bytes, ip1y.bytes, k.bytes);

	var zcu crypto.Key                   //  rct::key zcu;
	crypto.ScMul(&zcu, &zsq, &z)         //sc_mul(zcu.bytes, zsq.bytes, z.bytes);
	crypto.ScMulSub(&k, &zcu, &ip12, &k) //sc_mulsub(k.bytes, zcu.bytes, ip12.bytes, k.bytes);
	crypto.ScAdd(&t0, &t0, &k)           //sc_add(t0.bytes, t0.bytes, k.bytes);

	if DEBUGGING_MODE { // verify intermediate variables for correctness
		test_t0 := crypto.Zero                                  //rct::key test_t0 = rct::zero();
		iph := inner_product(aL[:], hadamard(aR[:], yN))        // rct::key iph = inner_product(aL, hadamard(aR, yN));
		crypto.ScAdd(&test_t0, &test_t0, &iph)                  //sc_add(test_t0.bytes, test_t0.bytes, iph.bytes);
		ips := inner_product(vector_subtract(aL[:], aR[:]), yN) //rct::key ips = inner_product(vector_subtract(aL, aR), yN);
		crypto.ScMulAdd(&test_t0, &z, &ips, &test_t0)           // sc_muladd(test_t0.bytes, z.bytes, ips.bytes, test_t0.bytes);
		ipt := inner_product(twoN, aL[:])                       // rct::key ipt = inner_product(twoN, aL);
		crypto.ScMulAdd(&test_t0, &zsq, &ipt, &test_t0)         // sc_muladd(test_t0.bytes, zsq.bytes, ipt.bytes, test_t0.bytes);
		crypto.ScAdd(&test_t0, &test_t0, &k)                    // sc_add(test_t0.bytes, test_t0.bytes, k.bytes);

		//CHECK_AND_ASSERT_THROW_MES(t0 == test_t0, "t0 check failed");
		if t0 != test_t0 {
			panic("t0 check failed")
		}

		//fmt.Printf("t0      %s\ntest_t0 %s\n",t0,test_t0)

	}

	// STEP 1 complete above

	// STEP 2 starts

	HyNsR := hadamard(yN, sR[:])            // const auto HyNsR = hadamard(yN, sR);
	vpIz := vector_scalar(oneN, z)          //  const auto vpIz = vector_scalar(oneN, z);
	vp2zsq := vector_scalar(twoN, zsq)      //  const auto vp2zsq = vector_scalar(twoN, zsq);
	aL_vpIz := vector_subtract(aL[:], vpIz) //  const auto aL_vpIz = vector_subtract(aL, vpIz);
	aR_vpIz := vector_add(aR[:], vpIz)      //const auto aR_vpIz = vector_add(aR, vpIz);

	ip1 := inner_product(aL_vpIz, HyNsR) // rct::key ip1 = inner_product(aL_vpIz, HyNsR);
	crypto.ScAdd(&t1, &t1, &ip1)         //   sc_add(t1.bytes, t1.bytes, ip1.bytes);

	ip2 := inner_product(sL[:], vector_add(hadamard(yN, aR_vpIz), vp2zsq)) // rct::key ip2 = inner_product(sL, vector_add(hadamard(yN, aR_vpIz), vp2zsq));
	crypto.ScAdd(&t1, &t1, &ip2)                                           // sc_add(t1.bytes, t1.bytes, ip2.bytes);

	ip3 := inner_product(sL[:], HyNsR) // rct::key ip3 = inner_product(sL, HyNsR);
	crypto.ScAdd(&t2, &t2, &ip3)       //sc_add(t2.bytes, t2.bytes, ip3.bytes);

	// PAPER LINES 47-48
	tau1 := crypto.SkGen() //   rct::key tau1 = rct::skGen(), tau2 = rct::skGen();
	tau2 := crypto.SkGen()

	// rct::key T1 = rct::addKeys(rct::scalarmultKey(rct::H, t1), rct::scalarmultBase(tau1));
	tau1_base := crypto.ScalarmultBase(tau1)
	T1 := AddKeys_return(crypto.ScalarMultKey(&crypto.H, &t1), &tau1_base)

	//rct::key T2 = rct::addKeys(rct::scalarmultKey(rct::H, t2), rct::scalarmultBase(tau2));
	tau2_base := crypto.ScalarmultBase(tau2)
	T2 := AddKeys_return(crypto.ScalarMultKey(&crypto.H, &t2), &tau2_base)

	// PAPER LINES 49-51
	x := hash_cache_mash3(&hashcache, z, T1, T2) //rct::key x = hash_cache_mash(hash_cache, z, T1, T2);

	// PAPER LINES 52-53
	taux := crypto.Zero                        // rct::key taux = rct::zero();
	crypto.ScMul(&taux, &tau1, &x)             //sc_mul(taux.bytes, tau1.bytes, x.bytes);
	var xsq crypto.Key                         //rct::key xsq;
	crypto.ScMul(&xsq, &x, &x)                 //sc_mul(xsq.bytes, x.bytes, x.bytes);
	crypto.ScMulAdd(&taux, &tau2, &xsq, &taux) // sc_muladd(taux.bytes, tau2.bytes, xsq.bytes, taux.bytes);
	crypto.ScMulAdd(&taux, gamma, &zsq, &taux) //sc_muladd(taux.bytes, gamma.bytes, zsq.bytes, taux.bytes);

	var mu crypto.Key                     //rct::key mu;
	crypto.ScMulAdd(&mu, &x, rho, &alpha) //sc_muladd(mu.bytes, x.bytes, rho.bytes, alpha.bytes);

	// PAPER LINES 54-57
	l := vector_add(aL_vpIz, vector_scalar(sL[:], x))                                   //rct::keyV l = vector_add(aL_vpIz, vector_scalar(sL, x));
	r := vector_add(hadamard(yN, vector_add(aR_vpIz, vector_scalar(sR[:], x))), vp2zsq) // rct::keyV r = vector_add(hadamard(yN, vector_add(aR_vpIz, vector_scalar(sR, x))), vp2zsq);

	// STEP 2 complete

	// STEP 3 starts
	t := inner_product(l, r) //rct::key t = inner_product(l, r);

	//DEBUG: Test if the l and r vectors match the polynomial forms
	if DEBUGGING_MODE {
		var test_t crypto.Key

		crypto.ScMulAdd(&test_t, &t1, &x, &t0)       // sc_muladd(test_t.bytes, t1.bytes, x.bytes, t0.bytes);
		crypto.ScMulAdd(&test_t, &t2, &xsq, &test_t) //sc_muladd(test_t.bytes, t2.bytes, xsq.bytes, test_t.bytes);

		if test_t != t {
			//panic("test_t check failed")
		}

		//fmt.Printf("t      %s\ntest_t %s\n",t,test_t)
	}

	// PAPER LINES 32-33
	x_ip := hash_cache_mash4(&hashcache, x, taux, mu, t) //rct::key x_ip = hash_cache_mash(hash_cache, x, taux, mu, t);

	// These are used in the inner product rounds
	// declared in step 4 //size_t nprime = N;
	var Gprime, Hprime, aprime, bprime []crypto.Key
	Gprime = make([]crypto.Key, N, N) //rct::keyV Gprime(N);
	Hprime = make([]crypto.Key, N, N) //rct::keyV Hprime(N);
	aprime = make([]crypto.Key, N, N) // rct::keyV aprime(N);
	bprime = make([]crypto.Key, N, N) //rct::keyV bprime(N);

	yinv := invert_scalar(y)   //const rct::key yinv = invert(y);
	yinvpow := crypto.Identity //          rct::key yinvpow = rct::identity();

	for i := 0; i < N; i++ { ///for (size_t i = 0; i < N; ++i)
		Gprime[i] = Gi[i]                                     //                       Gprime[i] = Gi[i];
		Hprime[i] = *(crypto.ScalarMultKey(&Hi[i], &yinvpow)) //Hprime[i] = scalarmultKey(Hi[i], yinvpow);
		crypto.ScMul(&yinvpow, &yinvpow, &yinv)               //sc_mul(yinvpow.bytes, yinvpow.bytes, yinv.bytes);

		aprime[i] = l[i] // aprime[i] = l[i];
		bprime[i] = r[i] // bprime[i] = r[i];
	}

	// STEP 3 complete

	// STEP 4 starts
	round := 0
	nprime := N
	//var L,R,w [logN]crypto.Key  // w is the challenge x in the inner product protocol
	L := make([]crypto.Key, logN, logN)
	R := make([]crypto.Key, logN, logN)
	w := make([]crypto.Key, logN, logN)
	var tmp crypto.Key

	// PAPER LINE 13
	for nprime > 1 { // while (nprime > 1)
		// PAPER LINE 15
		nprime /= 2 // nprime /= 2;

		// PAPER LINES 16-17
		cL := inner_product(slice_vector(aprime[:], 0, nprime), slice_vector(bprime[:], nprime, len(bprime))) // rct::key cL = inner_product(slice(aprime, 0, nprime), slice(bprime, nprime, bprime.size()));
		cR := inner_product(slice_vector(aprime[:], nprime, len(aprime)), slice_vector(bprime[:], 0, nprime)) // rct::key cR = inner_product(slice(aprime, nprime, aprime.size()), slice(bprime, 0, nprime));

		// PAPER LINES 18-19
		//L[round] = vector_exponent_custom(slice(Gprime, nprime, Gprime.size()), slice(Hprime, 0, nprime), slice(aprime, 0, nprime), slice(bprime, nprime, bprime.size()));

		L[round] = vector_exponent_custom(slice_vector(Gprime[:], nprime, len(Gprime)), slice_vector(Hprime[:], 0, nprime), slice_vector(aprime[:], 0, nprime), slice_vector(bprime[:], nprime, len(bprime)))
		crypto.ScMul(&tmp, &cL, &x_ip)                                              //    sc_mul(tmp.bytes, cL.bytes, x_ip.bytes);
		crypto.AddKeys(&L[round], &L[round], crypto.ScalarMultKey(&crypto.H, &tmp)) //rct::addKeys(L[round], L[round], rct::scalarmultKey(rct::H, tmp));
		//R[round] = vector_exponent_custom(slice(Gprime, 0, nprime), slice(Hprime, nprime, Hprime.size()), slice(aprime, nprime, aprime.size()), slice(bprime, 0, nprime));
		R[round] = vector_exponent_custom(slice_vector(Gprime[:], 0, nprime), slice_vector(Hprime[:], nprime, len(Hprime)), slice_vector(aprime[:], nprime, len(aprime)), slice_vector(bprime[:], 0, nprime))
		crypto.ScMul(&tmp, &cR, &x_ip)                                              // sc_mul(tmp.bytes, cR.bytes, x_ip.bytes);
		crypto.AddKeys(&R[round], &R[round], crypto.ScalarMultKey(&crypto.H, &tmp)) // rct::addKeys(R[round], R[round], rct::scalarmultKey(rct::H, tmp));

		// PAPER LINES 21-22
		w[round] = hash_cache_mash2(&hashcache, L[round], R[round]) //   w[round] = hash_cache_mash(hash_cache, L[round], R[round]);

		// PAPER LINES 24-25
		winv := invert_scalar(w[round]) //const rct::key winv = invert(w[round]);
		//Gprime = hadamard2(vector_scalar2(slice(Gprime, 0, nprime), winv), vector_scalar2(slice(Gprime, nprime, Gprime.size()), w[round]));
		Gprime = hadamard2(vector_scalar2(slice_vector(Gprime[:], 0, nprime), winv), vector_scalar2(slice_vector(Gprime[:], nprime, len(Gprime)), w[round]))

		//Hprime = hadamard2(vector_scalar2(slice(Hprime, 0, nprime), w[round]), vector_scalar2(slice(Hprime, nprime, Hprime.size()), winv));
		Hprime = hadamard2(vector_scalar2(slice_vector(Hprime[:], 0, nprime), w[round]), vector_scalar2(slice_vector(Hprime[:], nprime, len(Hprime)), winv))

		// PAPER LINES 28-29
		//aprime = vector_add(vector_scalar(slice(aprime, 0, nprime), w[round]), vector_scalar(slice(aprime, nprime, aprime.size()), winv));
		aprime = vector_add(vector_scalar(slice_vector(aprime[:], 0, nprime), w[round]), vector_scalar(slice_vector(aprime[:], nprime, len(aprime)), winv))

		//bprime = vector_add(vector_scalar(slice(bprime, 0, nprime), winv), vector_scalar(slice(bprime, nprime, bprime.size()), w[round]));
		bprime = vector_add(vector_scalar(slice_vector(bprime[:], 0, nprime), winv), vector_scalar(slice_vector(bprime[:], nprime, len(bprime)), w[round]))

		round++

	}
	return &BulletProof{
		V:    []crypto.Key{V},
		A:    A,
		S:    S,
		T1:   T1,
		T2:   T2,
		taux: taux,
		mu:   mu,
		L:    L,
		R:    R,
		a:    aprime[0],
		b:    bprime[0],
		t:    t,
	}
}

//BULLETPROOF_Prove_Amount_WithRegulation proves an amount with regulation
func BULLETPROOF_Prove_Amount_WithRegulation_Raw(v uint64, gamma *crypto.Key, sL, sR *[64]crypto.Key, rho *crypto.Key) *BulletProof {
	sv := crypto.Zero

	sv[0] = byte(v & 255)
	sv[1] = byte((v >> 8) & 255)
	sv[2] = byte((v >> 16) & 255)
	sv[3] = byte((v >> 24) & 255)
	sv[4] = byte((v >> 32) & 255)
	sv[5] = byte((v >> 40) & 255)
	sv[6] = byte((v >> 48) & 255)
	sv[7] = byte((v >> 56) & 255)

	return BULLETPROOF_Prove_WithRegulation_Raw(&sv, gamma, sL, sR, rho)
}

//BULLETPROOF_Prove_WithRegulation : Given a value v (0..2^N-1) and a mask gamma, construct a range proof
func BULLETPROOF_Prove_WithRegulation_Raw(sv *crypto.Key, gamma *crypto.Key, sL, sR *[64]crypto.Key, rho *crypto.Key) *BulletProof {
	const logN = int(6) // log2(64)
	const N = int(64)   // 1 << logN

	var V crypto.Key
	var aL, aR [N]crypto.Key
	var A, S crypto.Key

	// prove V
	crypto.AddKeys2(&V, gamma, sv, &crypto.H)

	// prove aL,aR
	// the entire amount in uint64 is extracted into bits and
	// different action taken if bit is zero or bit is one
	for i := N - 1; i >= 0; i-- {
		if (sv[i/8] & (1 << (uint64(i) % 8))) >= 1 {
			aL[i] = crypto.Identity
		} else {
			aL[i] = crypto.Zero
		}
		crypto.ScSub(&aR[i], &aL[i], &crypto.Identity)
	}

	hashcache := *(crypto.HashToScalar(V[:]))

	// prove STEP 1

	// PAPER LINES 38-39
	alpha := crypto.SkGen()
	ve := vector_exponent(aL[:], aR[:])

	alpha_base_tmp := crypto.ScalarmultBase(alpha)
	crypto.AddKeys(&A, &ve, &alpha_base_tmp)

	// PAPER LINES 40-42
	// var sL, sR [N]crypto.Key
	// for i := range sL {
	// 	sL[i] = crypto.SkGen()
	// 	sR[i] = crypto.SkGen()
	// }
	// //rct::keyV sL = rct::skvGen(N), sR = rct::skvGen(N);
	// rho := crypto.SkGen()
	ve = vector_exponent(sL[:], sR[:])
	rho_base_tmp := crypto.ScalarmultBase(*rho)
	crypto.AddKeys(&S, &ve, &rho_base_tmp)

	// PAPER LINES 43-45
	y := hash_cache_mash2(&hashcache, A, S)  //   rct::key y = hash_cache_mash(hash_cache, A, S);
	hashcache = *(crypto.HashToScalar(y[:])) // rct::key z = hash_cache = rct::hash_to_scalar(y);
	z := hashcache

	// Polynomial construction before PAPER LINE 46
	t0 := crypto.Zero // rct::key t0 = rct::zero();
	t1 := crypto.Zero // rct::key t1 = rct::zero();
	t2 := crypto.Zero // rct::key t2 = rct::zero();

	yN := vector_powers(y, int64(N)) // const auto yN = vector_powers(y, N);

	ip1y := inner_product(oneN, yN)      //rct::key ip1y = inner_product(oneN, yN);
	crypto.ScMulAdd(&t0, &z, &ip1y, &t0) // sc_muladd(t0.bytes, z.bytes, ip1y.bytes, t0.bytes);

	var zsq crypto.Key                  //rct::key zsq;
	crypto.ScMul(&zsq, &z, &z)          // sc_mul(zsq.bytes, z.bytes, z.bytes);
	crypto.ScMulAdd(&t0, &zsq, sv, &t0) // sc_muladd(t0.bytes, zsq.bytes, sv.bytes, t0.bytes);

	k := crypto.Zero                     // rct::key k = rct::zero();
	crypto.ScMulSub(&k, &zsq, &ip1y, &k) //sc_mulsub(k.bytes, zsq.bytes, ip1y.bytes, k.bytes);

	var zcu crypto.Key                   //  rct::key zcu;
	crypto.ScMul(&zcu, &zsq, &z)         //sc_mul(zcu.bytes, zsq.bytes, z.bytes);
	crypto.ScMulSub(&k, &zcu, &ip12, &k) //sc_mulsub(k.bytes, zcu.bytes, ip12.bytes, k.bytes);
	crypto.ScAdd(&t0, &t0, &k)           //sc_add(t0.bytes, t0.bytes, k.bytes);

	if DEBUGGING_MODE { // verify intermediate variables for correctness
		test_t0 := crypto.Zero                                  //rct::key test_t0 = rct::zero();
		iph := inner_product(aL[:], hadamard(aR[:], yN))        // rct::key iph = inner_product(aL, hadamard(aR, yN));
		crypto.ScAdd(&test_t0, &test_t0, &iph)                  //sc_add(test_t0.bytes, test_t0.bytes, iph.bytes);
		ips := inner_product(vector_subtract(aL[:], aR[:]), yN) //rct::key ips = inner_product(vector_subtract(aL, aR), yN);
		crypto.ScMulAdd(&test_t0, &z, &ips, &test_t0)           // sc_muladd(test_t0.bytes, z.bytes, ips.bytes, test_t0.bytes);
		ipt := inner_product(twoN, aL[:])                       // rct::key ipt = inner_product(twoN, aL);
		crypto.ScMulAdd(&test_t0, &zsq, &ipt, &test_t0)         // sc_muladd(test_t0.bytes, zsq.bytes, ipt.bytes, test_t0.bytes);
		crypto.ScAdd(&test_t0, &test_t0, &k)                    // sc_add(test_t0.bytes, test_t0.bytes, k.bytes);

		//CHECK_AND_ASSERT_THROW_MES(t0 == test_t0, "t0 check failed");
		if t0 != test_t0 {
			panic("t0 check failed")
		}

		//fmt.Printf("t0      %s\ntest_t0 %s\n",t0,test_t0)

	}

	// STEP 1 complete above

	// STEP 2 starts

	HyNsR := hadamard(yN, sR[:])            // const auto HyNsR = hadamard(yN, sR);
	vpIz := vector_scalar(oneN, z)          //  const auto vpIz = vector_scalar(oneN, z);
	vp2zsq := vector_scalar(twoN, zsq)      //  const auto vp2zsq = vector_scalar(twoN, zsq);
	aL_vpIz := vector_subtract(aL[:], vpIz) //  const auto aL_vpIz = vector_subtract(aL, vpIz);
	aR_vpIz := vector_add(aR[:], vpIz)      //const auto aR_vpIz = vector_add(aR, vpIz);

	ip1 := inner_product(aL_vpIz, HyNsR) // rct::key ip1 = inner_product(aL_vpIz, HyNsR);
	crypto.ScAdd(&t1, &t1, &ip1)         //   sc_add(t1.bytes, t1.bytes, ip1.bytes);

	ip2 := inner_product(sL[:], vector_add(hadamard(yN, aR_vpIz), vp2zsq)) // rct::key ip2 = inner_product(sL, vector_add(hadamard(yN, aR_vpIz), vp2zsq));
	crypto.ScAdd(&t1, &t1, &ip2)                                           // sc_add(t1.bytes, t1.bytes, ip2.bytes);

	ip3 := inner_product(sL[:], HyNsR) // rct::key ip3 = inner_product(sL, HyNsR);
	crypto.ScAdd(&t2, &t2, &ip3)       //sc_add(t2.bytes, t2.bytes, ip3.bytes);

	// PAPER LINES 47-48
	tau1 := crypto.SkGen() //   rct::key tau1 = rct::skGen(), tau2 = rct::skGen();
	tau2 := crypto.SkGen()

	// rct::key T1 = rct::addKeys(rct::scalarmultKey(rct::H, t1), rct::scalarmultBase(tau1));
	tau1_base := crypto.ScalarmultBase(tau1)
	T1 := AddKeys_return(crypto.ScalarMultKey(&crypto.H, &t1), &tau1_base)

	//rct::key T2 = rct::addKeys(rct::scalarmultKey(rct::H, t2), rct::scalarmultBase(tau2));
	tau2_base := crypto.ScalarmultBase(tau2)
	T2 := AddKeys_return(crypto.ScalarMultKey(&crypto.H, &t2), &tau2_base)

	// PAPER LINES 49-51
	x := hash_cache_mash3(&hashcache, z, T1, T2) //rct::key x = hash_cache_mash(hash_cache, z, T1, T2);

	// PAPER LINES 52-53
	taux := crypto.Zero                        // rct::key taux = rct::zero();
	crypto.ScMul(&taux, &tau1, &x)             //sc_mul(taux.bytes, tau1.bytes, x.bytes);
	var xsq crypto.Key                         //rct::key xsq;
	crypto.ScMul(&xsq, &x, &x)                 //sc_mul(xsq.bytes, x.bytes, x.bytes);
	crypto.ScMulAdd(&taux, &tau2, &xsq, &taux) // sc_muladd(taux.bytes, tau2.bytes, xsq.bytes, taux.bytes);
	crypto.ScMulAdd(&taux, gamma, &zsq, &taux) //sc_muladd(taux.bytes, gamma.bytes, zsq.bytes, taux.bytes);

	var mu crypto.Key                     //rct::key mu;
	crypto.ScMulAdd(&mu, &x, rho, &alpha) //sc_muladd(mu.bytes, x.bytes, rho.bytes, alpha.bytes);

	// PAPER LINES 54-57
	l := vector_add(aL_vpIz, vector_scalar(sL[:], x))                                   //rct::keyV l = vector_add(aL_vpIz, vector_scalar(sL, x));
	r := vector_add(hadamard(yN, vector_add(aR_vpIz, vector_scalar(sR[:], x))), vp2zsq) // rct::keyV r = vector_add(hadamard(yN, vector_add(aR_vpIz, vector_scalar(sR, x))), vp2zsq);

	// STEP 2 complete

	// STEP 3 starts
	t := inner_product(l, r) //rct::key t = inner_product(l, r);
	//fmt.Println("In raw, V = ", []crypto.Key{V}, " , mu = ", mu)
	return &BulletProof{
		V:    []crypto.Key{V},
		A:    A,
		S:    S,
		T1:   T1,
		T2:   T2,
		taux: taux,
		mu:   mu,
		L:    l,
		R:    r,
		t:    t,
	}
}

func (proof *BulletProof) BULLETPROOF_BasicChecks_Raw() (result bool) {

	// check whether any of the values in the proof are not 0 or 1
	if proof.V[0] == crypto.Zero ||
		proof.A == crypto.Zero ||
		proof.S == crypto.Zero ||
		proof.T1 == crypto.Zero ||
		proof.T2 == crypto.Zero ||
		proof.taux == crypto.Zero ||
		proof.mu == crypto.Zero ||
		proof.t == crypto.Zero {
		return false
	}
	for i := range proof.L {
		if proof.L[i] == crypto.Zero || proof.R[i] == crypto.Zero {
			return false
		}
	}

	if proof.V[0] == crypto.Identity ||
		proof.A == crypto.Identity ||
		proof.S == crypto.Identity ||
		proof.T1 == crypto.Identity ||
		proof.T2 == crypto.Identity ||
		proof.taux == crypto.Identity ||
		proof.mu == crypto.Identity ||
		proof.t == crypto.Identity {
		return false
	}
	for i := range proof.L {
		if proof.L[i] == crypto.Identity || proof.R[i] == crypto.Identity {
			return false
		}
	}
	// time to verify that cofactors cannnot be exploited
	curve_order := crypto.CurveOrder()
	if *crypto.ScalarMultKey(&proof.V[0], &curve_order) != crypto.Identity {
		return false
	}

	if *crypto.ScalarMultKey(&proof.A, &curve_order) != crypto.Identity {
		return false
	}
	if *crypto.ScalarMultKey(&proof.S, &curve_order) != crypto.Identity {
		return false
	}
	if *crypto.ScalarMultKey(&proof.T1, &curve_order) != crypto.Identity {
		return false
	}
	if *crypto.ScalarMultKey(&proof.T2, &curve_order) != crypto.Identity {
		return false
	}

	return true
}

func (proof *BulletProof) BULLETPROOF_Verify_Raw_ultrafast() (result bool) {

	defer func() { // safety so if anything wrong happens, verification fails
		if r := recover(); r != nil {
			result = false
		}
	}()

	//ultraonce.Do(precompute_tables_ultra) // generate pre compute tables

	N := 64

	if !(len(proof.V) == 1) {
		//V does not have exactly one element
		return false
	}

	if len(proof.L) != len(proof.R) {
		//Mismatched L and R sizes
		return false
	}
	if len(proof.L) == 0 {
		// Empty Proof
		return false
	}

	if len(proof.L) != N {
		//Proof is not for 64 bits
		return false
	}

	// these checks try to filter out rogue inputs
	if proof.BULLETPROOF_BasicChecks_Raw() == false {
		return false
	}
	// reconstruct the challenges
	hashcache := *(crypto.HashToScalar(proof.V[0][:]))  //rct::key hash_cache = rct::hash_to_scalar(proof.V[0]);
	y := hash_cache_mash2(&hashcache, proof.A, proof.S) //  rct::key y = hash_cache_mash(hash_cache, proof.A, proof.S);

	hashcache = *(crypto.HashToScalar(y[:])) // rct::key z = hash_cache = rct::hash_to_scalar(y);
	z := hashcache
	x := hash_cache_mash3(&hashcache, z, proof.T1, proof.T2) //rct::key x = hash_cache_mash(hash_cache, z, proof.T1, proof.T2);

	// PAPER LINE 61
	//rct::key L61Left = rct::addKeys(rct::scalarmultBase(proof.taux), rct::scalarmultKey(rct::H, proof.t));
	taux_base := crypto.ScalarmultBase(proof.taux)
	L61Left := AddKeys_return(&taux_base, crypto.ScalarMultKey(&crypto.H, &proof.t))

	k := crypto.Zero                 //rct::key k = rct::zero();
	yN := vector_powers(y, int64(N)) //const auto yN = vector_powers(y, N);
	ip1y := inner_product(oneN, yN)  //rct::key ip1y = inner_product(oneN, yN);
	zsq := crypto.Zero               //rct::key zsq;
	crypto.ScMul(&zsq, &z, &z)       //sc_mul(zsq.bytes, z.bytes, z.bytes);

	var tmp crypto.Key                   //rct::key tmp, tmp2;
	crypto.ScMulSub(&k, &zsq, &ip1y, &k) //  sc_mulsub(k.bytes, zsq.bytes, ip1y.bytes, k.bytes);
	var zcu crypto.Key                   //rct::key zcu;
	crypto.ScMul(&zcu, &zsq, &z)         //sc_mul(zcu.bytes, zsq.bytes, z.bytes);
	crypto.ScMulSub(&k, &zcu, &ip12, &k) //sc_mulsub(k.bytes, zcu.bytes, ip12.bytes, k.bytes);

	crypto.ScMulAdd(&tmp, &z, &ip1y, &k)                 // sc_muladd(tmp.bytes, z.bytes, ip1y.bytes, k.bytes);
	L61Right := *(crypto.ScalarMultKey(&crypto.H, &tmp)) //rct::key L61Right = rct::scalarmultKey(rct::H, tmp);

	tmp = *(crypto.ScalarMultKey(&proof.V[0], &zsq)) //tmp = rct::scalarmultKey(proof.V[0], zsq);
	crypto.AddKeys(&L61Right, &L61Right, &tmp)       //rct::addKeys(L61Right, L61Right, tmp);

	tmp = *(crypto.ScalarMultKey(&proof.T1, &x)) // tmp = rct::scalarmultKey(proof.T1, x);
	crypto.AddKeys(&L61Right, &L61Right, &tmp)   //ct::addKeys(L61Right, L61Right, tmp);

	var xsq crypto.Key                             //rct::key xsq;
	crypto.ScMul(&xsq, &x, &x)                     // sc_mul(xsq.bytes, x.bytes, x.bytes);
	tmp = *(crypto.ScalarMultKey(&proof.T2, &xsq)) //tmp = rct::scalarmultKey(proof.T2, xsq);
	crypto.AddKeys(&L61Right, &L61Right, &tmp)     //rct::addKeys(L61Right, L61Right, tmp);

	if !(L61Right == L61Left) {
		//MERROR("Verification failure at step 1");
		// fmt.Printf("erification failure at step 1")
		//fmt.Println("return false here111")
		return false
	}

	//fmt.Println("Verification passed at step 1")

	// PAPER LINE 62
	P := AddKeys_return(&proof.A, crypto.ScalarMultKey(&proof.S, &x)) //rct::key P = rct::addKeys(proof.A, rct::scalarmultKey(proof.S, x));
	/////////////////////////////////////////////////////////////////////////////////////
	//fmt.Println("P0 in verification raw = ", P)
	//h_base_scalar = y^{-i + 1}, i \in [1,n]
	h_base_scalar := make([]crypto.Key, N, N)
	yinv := invert_scalar(y) //const rct::key yinv = invert(y);
	yinvpow := y

	//fmt.Println("here yinv = ", yinv)
	for i := 0; i < N; i++ {
		crypto.ScMul(&yinvpow, &yinvpow, &yinv)
		h_base_scalar[i] = yinvpow
		//	fmt.Println("here y = ", h_base_scalar[i])
	}
	//fmt.Println("Verification passed at step 2")
	//g_scalar = z, h_scalar = z * y^n + z^2 * 2^n
	g_scalar := make([]crypto.Key, N, N)
	h_scalar := make([]crypto.Key, N, N)
	vp2zsq := vector_scalar(twoN, zsq)
	//ypow := yinv
	//fmt.Println("Verification passed at step 2.1")
	for i := 0; i < N; i++ {
		//fmt.Println("i = ", i)
		tmp := crypto.Zero
		g_scalar[i] = z
		h_scalar[i] = crypto.Zero
		//fmt.Println("here i = ", i)

		crypto.ScMul(&tmp, &z, &yN[i])
		//fmt.Println("3here i = ", i)
		//ScMulAdd(s,a,b,c), s = c + ab
		crypto.ScAdd(&tmp, &vp2zsq[i], &tmp)
		//fmt.Println("4here i = ", i)
		//tmp = z * y^n + z^2 * 2^n
		crypto.ScSub(&h_scalar[i], &h_scalar[i], &tmp)
		//fmt.Println("i = ", i)
	}
	//fmt.Println("Verification passed at step 3")
	g_scalar = vector_add(proof.L, g_scalar)
	h_scalar = vector_add(proof.R, h_scalar)
	h_scalar = hadamard(h_scalar, h_base_scalar)
	inner_prod := vector_exponent(g_scalar[:], h_scalar[:])
	//inner_prod := vector_exponent(h_scalar[:], g_scalar[:])
	tmp = crypto.ScalarmultBase(proof.mu)
	crypto.AddKeys(&tmp, &tmp, &inner_prod)
	//fmt.Println("Verification passed at step 4")
	if P != tmp {
		// fmt.Println("P = ", P)
		// fmt.Println("tmp = ", tmp)
		// fmt.Println("return false here9")
		return false
	}
	return true
}

//Given a set of values v (0..2^N-1) and masks gamma, construct a range proof
func BULLETPROOF_Prove2_WithRegulation(sv []crypto.Key, gamma []crypto.Key, sL, sR []crypto.Key, rho crypto.Key) *BulletProof {

	if len(sv) != len(gamma) {
		return nil
	}

	const logN = int(6) // log2(64)
	const N = int(64)   // 1 << logN
	var M, logM int
	for {
		M = 1 << uint(logM)
		if M <= maxM && M < len(sv) {
			logM++
		} else {
			break
		}
	}
	if M > maxM {
		// sv/gamma are too large
		return nil
	}

	MN := M * N

	if len(sL) != MN || len(sR) != MN {
		return nil
	}

	V := make([]crypto.Key, len(sv))
	aL := make([]crypto.Key, MN)
	aR := make([]crypto.Key, MN)
	aL8 := make([]crypto.Key, MN)
	aR8 := make([]crypto.Key, MN)
	var tmp, tmp2 crypto.Key

	// prove V
	for i := range sv {
		var gamma8, sv8 crypto.Key
		crypto.ScMul(&gamma8, &gamma[i], &crypto.INV_EIGHT)
		crypto.ScMul(&sv8, &sv[i], &crypto.INV_EIGHT)
		crypto.AddKeys2(&V[i], &gamma8, &sv8, &crypto.H)
	}

	// prove aL,aR
	// the entire amount in uint64 is extracted into bits and
	// different action taken if bit is zero or bit is one
	for j := 0; j < M; j++ {
		for i := N - 1; i >= 0; i-- {
			if j < len(sv) && (sv[j][i/8]&(1<<(uint64(i)%8))) != 0 {
				aL[j*N+i] = crypto.Identity
				aL8[j*N+i] = crypto.INV_EIGHT
				aR[j*N+i] = crypto.Zero
				aR8[j*N+i] = crypto.Zero
			} else {
				aL[j*N+i] = crypto.Zero
				aL8[j*N+i] = crypto.Zero
				aR[j*N+i] = crypto.MINUS_ONE
				aR8[j*N+i] = crypto.MINUS_INV_EIGHT
			}
		}
	}

	//for j := 0; j < M; j++ {
	//	var test_aL, test_aR uint64
	//	for i := 0; i < N; i++ {
	//		if bytes.Equal(aL[j*N+1][:], crypto.Identity[:]) {
	//			test_aL += 1 << uint(i)
	//		}
	//		if bytes.Equal(aR[j*N+1][:], crypto.Zero[:]) {
	//			test_aR += 1 << uint(i)
	//		}
	//	}
	//	var v_test uint64
	//	if j < len(sv) {
	//		for n := 0; n < 8; n++ {
	//			v_test |= uint64(sv[j][n]) << uint(8*n)
	//		}
	//	}
	//	if test_aL != v_test {
	//		panic("test_aL failed")
	//	}
	//	if test_aR != v_test {
	//		panic("test_aL failed")
	//	}
	//}

try_again:
	hashcache := *(crypto.HashToScalar2(V...))

	// prove STEP 1

	// PAPER LINES 38-39
	alpha := crypto.SkGen()
	ve := vector_exponent(aL8, aR8)
	var A crypto.Key
	crypto.ScMul(&tmp, &alpha, &crypto.INV_EIGHT)
	alphaTmp := crypto.ScalarmultBase(tmp)
	crypto.AddKeys(&A, &ve, &alphaTmp)

	// PAPER LINES 40-42
	// sL := make([]crypto.Key, MN)
	// sR := make([]crypto.Key, MN)
	// for i := range sL {
	// 	sL[i] = crypto.SkGen()
	// 	sR[i] = crypto.SkGen()
	// }
	//rct::keyV sL = rct::skvGen(N), sR = rct::skvGen(N);
	//rho := crypto.SkGen()
	ve = vector_exponent(sL[:], sR[:])
	var S crypto.Key
	rho_base_tmp := crypto.ScalarmultBase(rho)
	crypto.AddKeys(&S, &ve, &rho_base_tmp)
	S = *crypto.ScalarMultKey(&S, &crypto.INV_EIGHT)

	// PAPER LINES 43-45
	y := hash_cache_mash2(&hashcache, A, S) //   rct::key y = hash_cache_mash(hash_cache, A, S);
	if bytes.Equal(y[:], crypto.Zero[:]) {
		// y is 0, trying again
		goto try_again
	}
	hashcache = *(crypto.HashToScalar(y[:])) // rct::key z = hash_cache = rct::hash_to_scalar(y);
	z := hashcache
	if bytes.Equal(z[:], crypto.Zero[:]) {
		// z is 0, trying again
		goto try_again
	}

	l0 := vector_subtract_single(aL, &z)
	l1 := &sL

	zero_twos := make([]crypto.Key, MN)
	zpow := vector_powers(z, int64(M+2))
	for i := 0; i < MN; i++ {
		zero_twos[i] = crypto.Zero
		for j := 1; j <= M; j++ {
			if i >= (j-1)*N && i < j*N {
				crypto.ScMulAdd(&zero_twos[i], &zpow[1+j], &twoN[i-(j-1)*N], &zero_twos[i])
			}
		}
	}

	r0 := vector_add_single(aR, &z)
	yMN := vector_powers(y, int64(MN))
	r0 = hadamard(r0, yMN)
	r0 = vector_add(r0, zero_twos)
	r1 := hadamard(yMN, sR)

	// Polynomial construction before PAPER LINE 46
	t1_1 := inner_product(l0, r1)
	t1_2 := inner_product(*l1, r0)
	var t1 crypto.Key
	crypto.ScAdd(&t1, &t1_1, &t1_2)
	t2 := inner_product(*l1, r1)

	// PAPER LINES 47-48
	tau1 := crypto.SkGen() //   rct::key tau1 = rct::skGen(), tau2 = rct::skGen();
	tau2 := crypto.SkGen()

	var T1, T2 crypto.Key
	var p3 crypto.ExtendedGroupElement
	var ge_p3_H crypto.ExtendedGroupElement
	ge_p3_H.FromBytes(&crypto.H)
	crypto.ScMul(&tmp, &t1, &crypto.INV_EIGHT)
	crypto.ScMul(&tmp2, &tau1, &crypto.INV_EIGHT)
	crypto.GeDoubleScalarMultVartime2(&p3, &tmp, &ge_p3_H, &tmp2)
	p3.ToBytes(&T1)
	crypto.ScMul(&tmp, &t2, &crypto.INV_EIGHT)
	crypto.ScMul(&tmp2, &tau2, &crypto.INV_EIGHT)
	crypto.GeDoubleScalarMultVartime2(&p3, &tmp, &ge_p3_H, &tmp2)
	p3.ToBytes(&T2)

	// PAPER LINES 49-51
	x := hash_cache_mash3(&hashcache, z, T1, T2) //rct::key x = hash_cache_mash(hash_cache, z, T1, T2);
	if bytes.Equal(x[:], crypto.Zero[:]) {
		// x is 0, trying again
		goto try_again
	}

	// PAPER LINES 52-53
	taux := crypto.Zero                        // rct::key Taux = rct::zero();
	crypto.ScMul(&taux, &tau1, &x)             //sc_mul(Taux.bytes, tau1.bytes, x.bytes);
	var xsq crypto.Key                         //rct::key xsq;
	crypto.ScMul(&xsq, &x, &x)                 //sc_mul(xsq.bytes, x.bytes, x.bytes);
	crypto.ScMulAdd(&taux, &tau2, &xsq, &taux) // sc_muladd(Taux.bytes, tau2.bytes, xsq.bytes, Taux.bytes);
	for j := 1; j <= len(sv); j++ {
		crypto.ScMulAdd(&taux, &zpow[j+1], &gamma[j-1], &taux)
	}
	var mu crypto.Key                      //rct::key Mu;
	crypto.ScMulAdd(&mu, &x, &rho, &alpha) //sc_muladd(Mu.bytes, x.bytes, rho.bytes, alpha.bytes);

	// PAPER LINES 54-57
	l := vector_add(l0, vector_scalar(*l1, x)) //rct::keyV l = vector_add(aL_vpIz, vector_scalar(sL, x));
	r := vector_add(r0, vector_scalar(r1, x))  // rct::keyV r = vector_add(hadamard(yN, vector_add(aR_vpIz, vector_scalar(sR, x))), vp2zsq);

	// STEP 2 complete

	// STEP 3 starts
	t := inner_product(l, r) //rct::key t = inner_product(l, r);

	return &BulletProof{
		V:    V,
		A:    A,
		S:    S,
		T1:   T1,
		T2:   T2,
		taux: taux,
		mu:   mu,
		L:    l,
		R:    r,
		t:    t,
	}
}

//Given a set of values v (0..2^N-1) and masks gamma, construct a range proof
func BULLETPROOF_Prove2_raw(sv []crypto.Key, gamma []crypto.Key) *BulletProof {
	const logN = int(6) // log2(64)
	const N = int(64)   // 1 << logN
	var M, logM int
	for {
		M = 1 << uint(logM)
		if M <= maxM && M < len(sv) {
			logM++
		} else {
			break
		}
	}
	if M > maxM {
		// sv/gamma are too large
		return nil
	}
	MN := M * N

	V := make([]crypto.Key, len(sv))
	aL := make([]crypto.Key, MN)
	aR := make([]crypto.Key, MN)
	aL8 := make([]crypto.Key, MN)
	aR8 := make([]crypto.Key, MN)
	var tmp, tmp2 crypto.Key

	// prove V
	for i := range sv {
		var gamma8, sv8 crypto.Key
		crypto.ScMul(&gamma8, &gamma[i], &crypto.INV_EIGHT)
		crypto.ScMul(&sv8, &sv[i], &crypto.INV_EIGHT)
		crypto.AddKeys2(&V[i], &gamma8, &sv8, &crypto.H)
	}

	// prove aL,aR
	// the entire amount in uint64 is extracted into bits and
	// different action taken if bit is zero or bit is one
	for j := 0; j < M; j++ {
		for i := N - 1; i >= 0; i-- {
			if j < len(sv) && (sv[j][i/8]&(1<<(uint64(i)%8))) != 0 {
				aL[j*N+i] = crypto.Identity
				aL8[j*N+i] = crypto.INV_EIGHT
				aR[j*N+i] = crypto.Zero
				aR8[j*N+i] = crypto.Zero
			} else {
				aL[j*N+i] = crypto.Zero
				aL8[j*N+i] = crypto.Zero
				aR[j*N+i] = crypto.MINUS_ONE
				aR8[j*N+i] = crypto.MINUS_INV_EIGHT
			}
		}
	}

	//for j := 0; j < M; j++ {
	//	var test_aL, test_aR uint64
	//	for i := 0; i < N; i++ {
	//		if bytes.Equal(aL[j*N+1][:], crypto.Identity[:]) {
	//			test_aL += 1 << uint(i)
	//		}
	//		if bytes.Equal(aR[j*N+1][:], crypto.Zero[:]) {
	//			test_aR += 1 << uint(i)
	//		}
	//	}
	//	var v_test uint64
	//	if j < len(sv) {
	//		for n := 0; n < 8; n++ {
	//			v_test |= uint64(sv[j][n]) << uint(8*n)
	//		}
	//	}
	//	if test_aL != v_test {
	//		panic("test_aL failed")
	//	}
	//	if test_aR != v_test {
	//		panic("test_aL failed")
	//	}
	//}

try_again:
	hashcache := *(crypto.HashToScalar2(V...))

	// prove STEP 1

	// PAPER LINES 38-39
	alpha := crypto.SkGen()
	ve := vector_exponent(aL8, aR8)
	var A crypto.Key
	crypto.ScMul(&tmp, &alpha, &crypto.INV_EIGHT)
	alphaTmp := crypto.ScalarmultBase(tmp)
	crypto.AddKeys(&A, &ve, &alphaTmp)

	// PAPER LINES 40-42
	sL := make([]crypto.Key, MN)
	sR := make([]crypto.Key, MN)
	for i := range sL {
		sL[i] = crypto.SkGen()
		sR[i] = crypto.SkGen()
	}
	//rct::keyV sL = rct::skvGen(N), sR = rct::skvGen(N);
	rho := crypto.SkGen()
	ve = vector_exponent(sL[:], sR[:])
	var S crypto.Key
	rho_base_tmp := crypto.ScalarmultBase(rho)
	crypto.AddKeys(&S, &ve, &rho_base_tmp)
	S = *crypto.ScalarMultKey(&S, &crypto.INV_EIGHT)

	// PAPER LINES 43-45
	y := hash_cache_mash2(&hashcache, A, S) //   rct::key y = hash_cache_mash(hash_cache, A, S);
	if bytes.Equal(y[:], crypto.Zero[:]) {
		// y is 0, trying again
		goto try_again
	}
	hashcache = *(crypto.HashToScalar(y[:])) // rct::key z = hash_cache = rct::hash_to_scalar(y);
	z := hashcache
	if bytes.Equal(z[:], crypto.Zero[:]) {
		// z is 0, trying again
		goto try_again
	}

	l0 := vector_subtract_single(aL, &z)
	l1 := &sL

	zero_twos := make([]crypto.Key, MN)
	zpow := vector_powers(z, int64(M+2))
	for i := 0; i < MN; i++ {
		zero_twos[i] = crypto.Zero
		for j := 1; j <= M; j++ {
			if i >= (j-1)*N && i < j*N {
				crypto.ScMulAdd(&zero_twos[i], &zpow[1+j], &twoN[i-(j-1)*N], &zero_twos[i])
			}
		}
	}

	r0 := vector_add_single(aR, &z)
	yMN := vector_powers(y, int64(MN))
	r0 = hadamard(r0, yMN)
	r0 = vector_add(r0, zero_twos)
	r1 := hadamard(yMN, sR)

	// Polynomial construction before PAPER LINE 46
	t1_1 := inner_product(l0, r1)
	t1_2 := inner_product(*l1, r0)
	var t1 crypto.Key
	crypto.ScAdd(&t1, &t1_1, &t1_2)
	t2 := inner_product(*l1, r1)

	// PAPER LINES 47-48
	tau1 := crypto.SkGen() //   rct::key tau1 = rct::skGen(), tau2 = rct::skGen();
	tau2 := crypto.SkGen()

	var T1, T2 crypto.Key
	var p3 crypto.ExtendedGroupElement
	var ge_p3_H crypto.ExtendedGroupElement
	ge_p3_H.FromBytes(&crypto.H)
	crypto.ScMul(&tmp, &t1, &crypto.INV_EIGHT)
	crypto.ScMul(&tmp2, &tau1, &crypto.INV_EIGHT)
	crypto.GeDoubleScalarMultVartime2(&p3, &tmp, &ge_p3_H, &tmp2)
	p3.ToBytes(&T1)
	crypto.ScMul(&tmp, &t2, &crypto.INV_EIGHT)
	crypto.ScMul(&tmp2, &tau2, &crypto.INV_EIGHT)
	crypto.GeDoubleScalarMultVartime2(&p3, &tmp, &ge_p3_H, &tmp2)
	p3.ToBytes(&T2)

	// PAPER LINES 49-51
	x := hash_cache_mash3(&hashcache, z, T1, T2) //rct::key x = hash_cache_mash(hash_cache, z, T1, T2);
	if bytes.Equal(x[:], crypto.Zero[:]) {
		// x is 0, trying again
		goto try_again
	}

	// PAPER LINES 52-53
	taux := crypto.Zero                        // rct::key Taux = rct::zero();
	crypto.ScMul(&taux, &tau1, &x)             //sc_mul(Taux.bytes, tau1.bytes, x.bytes);
	var xsq crypto.Key                         //rct::key xsq;
	crypto.ScMul(&xsq, &x, &x)                 //sc_mul(xsq.bytes, x.bytes, x.bytes);
	crypto.ScMulAdd(&taux, &tau2, &xsq, &taux) // sc_muladd(Taux.bytes, tau2.bytes, xsq.bytes, Taux.bytes);
	for j := 1; j <= len(sv); j++ {
		crypto.ScMulAdd(&taux, &zpow[j+1], &gamma[j-1], &taux)
	}
	var mu crypto.Key                      //rct::key Mu;
	crypto.ScMulAdd(&mu, &x, &rho, &alpha) //sc_muladd(Mu.bytes, x.bytes, rho.bytes, alpha.bytes);

	// PAPER LINES 54-57
	l := vector_add(l0, vector_scalar(*l1, x)) //rct::keyV l = vector_add(aL_vpIz, vector_scalar(sL, x));
	r := vector_add(r0, vector_scalar(r1, x))  // rct::keyV r = vector_add(hadamard(yN, vector_add(aR_vpIz, vector_scalar(sR, x))), vp2zsq);

	// STEP 2 complete

	// STEP 3 starts
	t := inner_product(l, r) //rct::key t = inner_product(l, r);

	// PAPER LINES 32-33
	x_ip := hash_cache_mash4(&hashcache, x, taux, mu, t) //rct::key x_ip = hash_cache_mash(hash_cache, x, Taux, Mu, t);
	if bytes.Equal(x_ip[:], crypto.Zero[:]) {
		// x_ip is 0, trying again
		goto try_again
	}

	// These are used in the inner product rounds
	//nprime := MN
	var aprime, bprime []crypto.Key
	Gprime := make([]crypto.ExtendedGroupElement, MN) //rct::keyV Gprime(N);
	Hprime := make([]crypto.ExtendedGroupElement, MN) //rct::keyV Hprime(N);
	aprime = make([]crypto.Key, MN)                   // rct::keyV aprime(N);
	bprime = make([]crypto.Key, MN)                   //rct::keyV bprime(N);

	yinv := invert_scalar(y)          //const rct::key yinv = invert(y);
	yinvpow := make([]crypto.Key, MN) //          rct::key yinvpow = rct::identity();
	yinvpow[0] = crypto.Identity
	yinvpow[1] = yinv
	for i := 0; i < MN; i++ { ///for (size_t i = 0; i < N; ++i)
		Gprime[i] = Gi_p3[i] //                       Gprime[i] = Gi[i];
		Hprime[i] = Hi_p3[i] //Hprime[i] = scalarmultKey(Hi[i], yinvpow);
		if i > 1 {
			crypto.ScMul(&yinvpow[i], &yinvpow[i-1], &yinv)
		}
		aprime[i] = l[i] // aprime[i] = l[i];
		bprime[i] = r[i] // bprime[i] = r[i];
	}

	// STEP 3 complete

	return &BulletProof{
		V:    V,
		A:    A,
		S:    S,
		T1:   T1,
		T2:   T2,
		taux: taux,
		mu:   mu,
		L:    l,
		R:    r,
		t:    t,
	}
}

func BULLETPROOF_Verify2_Optimized_WithRegulation(proofs []BulletProof) bool {
	const logN = int(6) // log2(64)
	const N = int(64)   // 1 << logN
	max_length := 0
	nV := 0
	proof_data := make([]proof_data_t, len(proofs))
	//	inv_offset := 0
	//var to_invert []crypto.Key
	//	max_logM := 0
	for i_proofs := range proofs {
		proof := &proofs[i_proofs]
		// check scalar range
		if !crypto.Sc_check(&proof.taux) || !crypto.Sc_check(&proof.mu) || !crypto.Sc_check(&proof.a) || !crypto.Sc_check(&proof.b) || !crypto.Sc_check(&proof.t) {
			// Input scalar not in range
			return false
		}
		if len(proof.V) < 1 {
			// V does not have at least one element
			return false
		}
		if len(proof.L) != len(proof.R) {
			// Mismatched L and R sizes
			return false
		}
		if len(proof.L) < 1 {
			// Empty proof
			return false
		}
		if len(proof.L) > max_length {
			max_length = len(proof.L)
		}
		nV += len(proof.V)

		// Reconstruct the challenges
		pd := &proof_data[i_proofs]
		hash_cache := crypto.HashToScalar2(proof.V...)
		pd.y = hash_cache_mash2(hash_cache, proof.A, proof.S)
		if bytes.Equal(pd.y[:], crypto.Zero[:]) {
			return false
		}
		hash_cache = crypto.HashToScalar(pd.y[:])
		pd.z = *hash_cache
		if bytes.Equal(pd.z[:], crypto.Zero[:]) {
			return false
		}
		pd.x = hash_cache_mash3(hash_cache, pd.z, proof.T1, proof.T2)
		if bytes.Equal(pd.x[:], crypto.Zero[:]) {
			return false
		}
		pd.x_ip = hash_cache_mash4(hash_cache, pd.x, proof.taux, proof.mu, proof.t)
		if bytes.Equal(pd.x_ip[:], crypto.Zero[:]) {
			return false
		}

		M := 0
		pd.logM = 0
		for {
			M = 1 << uint(pd.logM)
			if M <= maxM && M < len(proof.V) {
				pd.logM++
			} else {
				break
			}
		}
		// if len(proof.L) != 6+pd.logM {
		// 	// Proof is not the expected size
		// 	return false
		// }
		// if max_logM < pd.logM {
		// 	max_logM = pd.logM
		// }

		// rounds := pd.logM + logN
		// if rounds < 1 {
		// 	// Zero rounds
		// 	return false
		// }

		// PAPER LINES 21-22
		// The inner product challenges are computed per round
		// pd.w = make([]crypto.Key, rounds)
		// for i := 0; i < rounds; i++ {
		// 	pd.w[i] = hash_cache_mash2(hash_cache, proof.L[i], proof.R[i])
		// 	if bytes.Equal(pd.w[i][:], crypto.Zero[:]) {
		// 		// w[i] == 0
		// 		return false
		// 	}
		// }

		// pd.inv_offset = inv_offset
		// for i := 0; i < rounds; i++ {
		// 	to_invert = append(to_invert, pd.w[i])
		// }
		// to_invert = append(to_invert, pd.y)
		// inv_offset += rounds + 1
	}

	// if max_length >= 32 {
	// 	// At least one proof is too large
	// 	return false
	// }
	maxMN := max_length
	//fmt.Println("MaxMN = ", maxMN)
	//twoMN := vector_powers(TWO, int64(maxMN))
	var tmp crypto.Key
	multiexp_data := make([]crypto.MultiexpData, 2*maxMN)

	//	inverse := invert(to_invert)

	// setup weighted aggregates
	z1 := crypto.Zero
	z3 := crypto.Zero
	m_z4 := make([]crypto.Key, maxMN)
	m_z5 := make([]crypto.Key, maxMN)
	m_y0 := crypto.Zero
	y1 := crypto.Zero
	proof_data_index := 0
	//var w_cache []crypto.Key
	for i_proofs := range proofs {
		proof := &proofs[i_proofs]
		pd := &proof_data[proof_data_index]
		proof_data_index++

		// if len(proof.L) != 6+pd.logM {
		// 	// Proof is not the expected size
		// 	return false
		// }
		M := 1 << uint(pd.logM)
		MN := M * N
		//fmt.Println("M = ", M, ", MN = ", MN)
		weight_y := crypto.SkGen()
		weight_z := crypto.SkGen()

		// pre-multiply some points by 8
		proof8_V := make([]crypto.Key, len(proof.V))
		for i := range proof.V {
			proof8_V[i] = *crypto.Scalarmult8(&proof.V[i])
		}
		proof8_L := make([]crypto.Key, len(proof.L))
		//fmt.Println("len of L = ", len(proof.L))
		for i := range proof.L {
			proof8_L[i] = proof.L[i]
		}
		proof8_R := make([]crypto.Key, len(proof.R))
		for i := range proof.R {
			proof8_R[i] = proof.R[i]
		}
		proof8_T1 := *crypto.Scalarmult8(&proof.T1)
		proof8_T2 := *crypto.Scalarmult8(&proof.T2)
		proof8_S := *crypto.Scalarmult8(&proof.S)
		proof8_A := *crypto.Scalarmult8(&proof.A)

		// PAPER LINE 61
		crypto.ScMulSub(&m_y0, &proof.taux, &weight_y, &m_y0)

		ypow := vector_powers(pd.y, int64(MN))
		zpow := vector_powers(pd.z, int64(M+3))

		var k crypto.Key
		ip1y := vector_power_sum(pd.y, MN)
		crypto.ScMulSub(&k, &zpow[2], &ip1y, &k)
		for j := 1; j <= M; j++ {
			if j+2 >= len(zpow) {
				// invalid zpow index
				return false
			}
			crypto.ScMulSub(&k, &zpow[j+2], &ip12, &k)
		}

		crypto.ScMulAdd(&tmp, &pd.z, &ip1y, &k)
		crypto.ScSub(&tmp, &proof.t, &tmp)
		crypto.ScMulAdd(&y1, &tmp, &weight_y, &y1)
		for j := 0; j < len(proof8_V); j++ {
			crypto.ScMul(&tmp, &zpow[j+2], &weight_y)
			crypto.AppendMultiexpData(&multiexp_data, &proof8_V[j], &tmp)
		}
		crypto.ScMul(&tmp, &pd.x, &weight_y)
		crypto.AppendMultiexpData(&multiexp_data, &proof8_T1, &tmp)
		var xsq crypto.Key
		crypto.ScMul(&xsq, &pd.x, &pd.x)
		crypto.ScMul(&tmp, &xsq, &weight_y)
		crypto.AppendMultiexpData(&multiexp_data, &proof8_T2, &tmp)

		// PAPER LINE 62
		crypto.AppendMultiexpData(&multiexp_data, &proof8_A, &weight_z)
		crypto.ScMul(&tmp, &pd.x, &weight_z)
		crypto.AppendMultiexpData(&multiexp_data, &proof8_S, &tmp)

		{
			h_base_scalar := make([]crypto.Key, MN, MN)
			yinv := invert_scalar(pd.y) //const rct::key yinv = invert(y);
			yinvpow := pd.y

			//fmt.Println("here yinv = ", yinv)
			for i := 0; i < MN; i++ {
				crypto.ScMul(&yinvpow, &yinvpow, &yinv)
				h_base_scalar[i] = yinvpow
				//	fmt.Println("here y = ", h_base_scalar[i])
			}
			//fmt.Println("Verification passed at step 2")
			//g_scalar = z, h_scalar = z * y^n + z^2 * 2^n
			g_scalar := make([]crypto.Key, MN, MN)
			h_scalar := make([]crypto.Key, MN, MN)
			//vp2zsq := vector_scalar(twoN, zpow[2])
			//ypow := yinv
			//fmt.Println("Verification passed at step 2.1")
			for i := 0; i < MN; i++ {
				//fmt.Println("i = ", i)
				tmp := crypto.Zero
				h_scalar[i] = crypto.Zero
				crypto.ScSub(&g_scalar[i], &crypto.Zero, &pd.z)
				//g_scalar[i] = pd.z
				h_scalar[i] = crypto.Zero
				//fmt.Println("here i = ", i)
				crypto.ScMul(&tmp, &pd.z, &ypow[i])
				//fmt.Println("3here i = ", i)
				//ScMulAdd(s,a,b,c), s = c + ab
				//crypto.ScAdd(&tmp, &vp2zsq[i], &tmp)
				//j := i / N
				//iDivided := i % N
				//fmt.Println("test here i = ", i, ", j + 1 = ", 2+i/N)
				crypto.ScMulAdd(&tmp, &twoN[i%N], &zpow[2+i/N], &tmp)
				crypto.ScAdd(&h_scalar[i], &h_scalar[i], &tmp)

				//deal with innner product
				crypto.ScSub(&g_scalar[i], &g_scalar[i], &proof.L[i])
				crypto.ScSub(&h_scalar[i], &h_scalar[i], &proof.R[i])
				crypto.ScMul(&h_scalar[i], &h_scalar[i], &h_base_scalar[i])
				//h_scalar = hadamard(h_scalar, h_base_scalar)
				//add to final scalar
				crypto.ScMulAdd(&m_z4[i], &g_scalar[i], &weight_z, &m_z4[i])
				crypto.ScMulAdd(&m_z5[i], &h_scalar[i], &weight_z, &m_z5[i])
				//fmt.Println("i = ", i)
			}
			//fmt.Println("Verification passed at step 3")
			// g_scalar = vector_add(proof.L, g_scalar)
			// h_scalar = vector_add(proof.R, h_scalar)
			//**g base scalar and h base scalar need to be updated

			//inner_prod := vector_exponent(g_scalar[:], h_scalar[:])
			//inner_prod := vector_exponent(h_scalar[:], g_scalar[:])
			//tmp = crypto.ScalarmultBase(proof.mu)
			//crypto.AddKeys(&tmp, &tmp, &inner_prod)
		}

		crypto.ScMulAdd(&z1, &proof.mu, &weight_z, &z1)

	}

	// now check all proofs at once
	crypto.ScSub(&tmp, &m_y0, &z1)
	crypto.AppendMultiexpData(&multiexp_data, &crypto.GBASE, &tmp)
	crypto.ScSub(&tmp, &z3, &y1)
	crypto.AppendMultiexpData(&multiexp_data, &crypto.H, &tmp)
	for i := 0; i < maxMN; i++ {
		multiexp_data[i*2].Scalar = m_z4[i]
		multiexp_data[i*2].Point = Gi_p3[i]
		multiexp_data[i*2+1].Scalar = m_z5[i]
		multiexp_data[i*2+1].Point = Hi_p3[i]
	}

	sum, err := crypto.Multiexp(&multiexp_data, 2*maxMN)
	if err != nil || !bytes.Equal(sum[:], crypto.Identity[:]) {
		// Verification failure
		return false
	}
	return true
}

func (proof *BulletProof) ExtractAmount(sL *[64]crypto.Key) (amount crypto.Key) {
	// reconstruct the challenges
	hashcache := *(crypto.HashToScalar(proof.V[0][:]))  //rct::key hash_cache = rct::hash_to_scalar(proof.V[0]);
	y := hash_cache_mash2(&hashcache, proof.A, proof.S) //  rct::key y = hash_cache_mash(hash_cache, proof.A, proof.S);

	hashcache = *(crypto.HashToScalar(y[:])) // rct::key z = hash_cache = rct::hash_to_scalar(y);
	z := hashcache
	x := hash_cache_mash3(&hashcache, z, proof.T1, proof.T2) //rct::key x = hash_cache_mash(hash_cache, z, proof.T1, proof.T2);
	aL_vpIz := vector_subtract(proof.L, vector_scalar(sL[:], x))
	vpIz := vector_scalar(oneN, z) //  const auto vpIz = vector_scalar(oneN, z);
	aL := vector_add(aL_vpIz, vpIz)
	for i := 0; i < len(aL); i++ {
		if aL[i] == crypto.Identity {
			amount[i/8] = amount[i/8] | (1 << uint(i%8))
		}
	}
	return amount
}
