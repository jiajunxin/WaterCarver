#include "WaterCarver.h"

#include "CipherTable.h"
#include "Functions.h"
#include "Utils.h"
#include "RemoteShuffler.h"
#include "FakeZZ.h"
#include "SchnorrProof.h"
#include "Pedersen.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>

extern G_q G;
extern vector<long> num;
static Mod_p G_h; //G_h is used for Pedersen Commitment
static bool G_hIsInit = false;

using namespace ::std;

void init_G_h()
{
    init();
    if (true == G_hIsInit)
    {
        return;
    }
    bool b = true;
    ZZ ran;
    Mod_p temp;
    while (b)
    {
        ran = RandomBnd(G.get_ord());

#if USE_REAL_POINTS
        ZZ mod = G.get_mod();
        CurvePoint x;
        basepoint_scalarmult(x, ran);
        temp = Mod_p(x, mod);
#else
        temp = G.get_gen().expo(to_ZZ(ran));
#endif
        if (G.is_generator(temp))
        {
            G_h = temp;
            b = false;
        }
    }
    G_hIsInit = true;
    return;
}

//	MulMod(temp_1,b.get_u(),c.get_u(),mod);
//a= Cipher_elg(temp_1,mod);

void genCommitments(vector<Mod_p> *vec, Pedersen *ped, long N)
{
    int i = 0;
    for (i = 0; i < N; i++)
    {
        ZZ x = RandomBnd(G.get_ord());
        ZZ r = RandomBnd(G.get_ord());
        // ZZ r2 = RandomBnd(G.get_ord());
        CurvePoint g;
        basepoint_scalarmult(g, x);
        //   Mod_p commit(g, G.get_mod());
        Mod_p commit = ped->commit(x, r);
        //cout<< "commit = " <<commit <<endl;
        (*vec)[i] = commit;
    }
    //std::cout << "The vector size =" << vec->size() << std::endl; //Todo:remove this line
    return;
}

void genRanNum(vector<ZZ> *ranNumVec, long N)
{
    int i = 0;
    for (i = 0; i < N; i++)
    {
        ZZ x = RandomBnd(G.get_ord());
        (*ranNumVec)[i] = x;
    }
    return;
}

CipherTable *arrangeTable(vector<Mod_p> *commitVector, long m, long n)
{
    //cout << "arrangeTable0 m = " << m << endl;
    init();
    vector<vector<Cipher_elg> *> *ciphers = new vector<vector<Cipher_elg> *>(m);
    //First generate vector<vector<Cipher_elg>* >* ciphers
    int i = 0;
    int j = 0;
    for (i = 0; i < m; i++)
    {
        vector<Cipher_elg> *v = new vector<Cipher_elg>(n);
        for (j = 0; j < n; j++)
        {
            Cipher_elg ce((*commitVector)[i * n + j]);
            (*v)[j] = ce;
        }
        (*ciphers)[i] = v;
    }
    //cout << "arrangeTable m = " << m << endl;
    CipherTable *ret = new CipherTable(ciphers, m);
    ret->set_dimentions(m, n);
    return ret;
}

void watercarver()
{
    auto tstart = high_resolution_clock::now();
    //cout << "Hello, World!" << endl;
    //First generate m*n pedersen commitments
    //should allow input m*n numbers, like several options
    //should allow input g and h for pedersen
    init();
    init_G_h();
    srand((unsigned int)time(NULL));

    resetM_N(64, 64);

    long m = getM();
    long n = 64;
    long N = m * n;

    vector<Mod_p> *commitVector;
    commitVector = new vector<Mod_p>(N);
    Mod_p gen[2] = {G.get_gen(), G_h};
    //    char Gstr[32];
    //    G.get_gen().get_val().serialize(Gstr);

    Pedersen ped(gen, 2);
    ped.set_omega(4, 5, 6);
    //Generate N Pedersen commitments with same G and H and each with a random number
    genCommitments(commitVector, &ped, N);

    vector<ZZ> *ranNumVec;
    ranNumVec = new vector<ZZ>(N);
    genRanNum(ranNumVec, N);
    //cout << "arrangeTable00 m = " << m << endl;
    CipherTable *ciphers = arrangeTable(commitVector, m, n);

    //end from Utils.cpp
    time_t parse_start = time(NULL);
    // cout << "parsing input1" << endl;
    string shuffle_input(ciphers->encode_all_ciphers());
    //cout << "done parsing. " << time(NULL) - parse_start << endl;

    char *shuffled_ciphers;
    int shuffled_ciphers_len;
    char *proof;
    int proof_len;
    int *permutation;
    int permutation_len;
    char *public_randoms;
    int public_randoms_len;
    //cout << "G order:" << G.get_ord() << endl;
    //cout << "shuffle begins!" << endl;
    ElGammal *elgammal = (ElGammal *)create_pub_key_use_dero_H();
    //cout << "after create_pub_key" << endl;
    time_t shuffle_time = time(NULL);
    char *input = (char *)shuffle_input.c_str();
    auto pi = new vector<vector<vector<long> *> *>(m);
    Permutation::perm_matrix(pi, n, m);
    auto R = new vector<vector<ZZ> *>(m);
    Functions::randomEl(R, m, n);
    void *cached_shuffle = shuffle_internal(elgammal, input, shuffle_input.size(), m * n,
                                            &shuffled_ciphers, &shuffled_ciphers_len, &permutation, &permutation_len, pi, R);
    //cout << "shuffle is done! In " << time(NULL) - shuffle_time << endl;

    //cout << "prove begins!" << endl;
    tstart = high_resolution_clock::now();
    prove(cached_shuffle, &proof, &proof_len, &public_randoms, &public_randoms_len);
    auto tstop = high_resolution_clock::now();
    auto time_di = duration<double>(tstop - tstart).count();
    //cout << "To calculate the proof took " << time_di << " sec." << endl;

    //cout << "verify begins!" << endl;
    tstart = high_resolution_clock::now();
    int ret = verify(1, proof, proof_len, input, shuffle_input.size(), shuffled_ciphers, shuffled_ciphers_len, nullptr, 0);
    tstop = high_resolution_clock::now();
    time_di = duration<double>(tstop - tstart).count();
    //cout << "To calculate the verify took " << time_di << " sec." << endl;
    //cout << "ret = " << ret << endl;

    //end from Utils.cpp

    delete ciphers;
    delete commitVector;
    delete ranNumVec;
    //std::cout << "Mension Accomplish!" << std::endl;

    //Shuffle the commitments with given random numbers
    //and pass the permutation to the prover

    return;
}

void testPoint()
{
    cout << "Hello, Point!" << endl;
    init();

    init_G_h();
    srand((unsigned int)time(NULL));

    long m = 2;
    long n = 2;
    long N = m * n;

    vector<Mod_p> *commitVector;
    commitVector = new vector<Mod_p>(N);
    Mod_p gen[2] = {G.get_gen(), G_h};

    Pedersen ped(gen, 2);
    ped.set_omega(4, 5, 6);

    //Generate N Pedersen commitments with same G and H and each with a random number
    genCommitments(commitVector, &ped, N);
    uint8_t buffer[32];
    uint8_t buffer2[32];
    cout << "test here before getval" << endl;
    CurvePoint cp = (*commitVector)[0].get_val();
    cout << "test here after getval" << endl;
    edgamal_compress_point(buffer, &(cp.P));
    cout << "test here after cp" << endl;
    int i = 0;
    cout << "buffer = ";
    while (i < 32)
    {
        cout << unsigned(buffer[i]);
        i++;
    }
    cout << endl;
    cout << "highest bit is " << unsigned(buffer[31]) << endl;
    edgamal_curve_point out;
    edgamal_decompress_point(&out, buffer);
    edgamal_compress_point(buffer2, &out);
    i = 0;
    cout << "buffer2 = ";
    while (i < 32)
    {
        cout << unsigned(buffer[i]);
        i++;
    }
    cout << endl;
    cout << "highest bit is " << unsigned(buffer[31]) << endl;

    cout << "another test!" << endl;
    char buffer3[128];
    cp.serialize(buffer3);
    CurvePoint recPt;
    recPt.deserialize(buffer3);

    delete commitVector;
    return;
}