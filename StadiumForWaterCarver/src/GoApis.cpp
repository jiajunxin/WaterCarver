//
// Created by wyongcan on 2019/10/14.
//

#include <iostream>
#include <vector>

#include "GoApis.h"
#include "ElGammal.h"
#include "Utils.h"
#include "CurvePoint.h"
#include "CipherTable.h"
#include "Permutation.h"

extern G_q G;
const int KEY_SIZE = 32;
ElGammal *elgammal = nullptr;

using namespace ::std;

void printKey(char *data, int len)
{
    for (int i = 0; i < len; i++)
    {
        printf("%02x", (unsigned char)data[i]);
    }
}

void shuffle_gen(char *commitments, int m, int n, char **shuffledCommitments, int *shuffledCommitmentsLen,
                 int **permutation, int *permutationLen, char **proof, int *proofLen)
{
    if (!elgammal)
    {
        elgammal = (ElGammal *)create_pub_key_use_dero_H();
    }
    init();
    resetM_N(m, n);
    ZZ mod = G.get_mod();
    auto ciphers = new vector<vector<Cipher_elg> *>(getM());
    for (int i = 0; i < m; i++)
    {
        auto v = new vector<Cipher_elg>(n);
        for (int j = 0; j < n; j++)
        {
            CurvePoint point;
            point.deserialize(&commitments[(i * n + j) * KEY_SIZE]);
            (*v)[j] = Cipher_elg(Mod_p(point, mod));
        }
        (*ciphers)[i] = v;
    }
    auto cipherTable = new CipherTable(ciphers, m);
    cipherTable->set_dimentions(m, n);
    string shuffle_input(cipherTable->encode_all_ciphers());
    for (auto &cipher : *ciphers)
    {
        delete cipher;
    }
    delete ciphers;
    ciphers = nullptr;
    delete cipherTable;
    cipherTable = nullptr;
    char *input = (char *)shuffle_input.c_str();
    char *shuffled_ciphers;
    int shuffled_ciphers_len;
    void *cached_shuffle = shuffle_internal(elgammal, input, shuffle_input.size(), m * n,
                                            &shuffled_ciphers, &shuffled_ciphers_len, permutation, permutationLen);
    prove(cached_shuffle, proof, proofLen, nullptr, nullptr);
    string inp(shuffled_ciphers, shuffled_ciphers_len);
    cipherTable = new CipherTable(inp, m, elgammal);
    ciphers = cipherTable->getCMatrix();
    m = cipherTable->rows();
    n = cipherTable->cols();
    *shuffledCommitmentsLen = m * n;
    *shuffledCommitments = new char[*shuffledCommitmentsLen * KEY_SIZE];
    for (int i = 0; i < m; i++)
    {
        auto v = ciphers->at(i);
        for (int j = 0; j < n; j++)
        {
            CurvePoint point;
            point = (*v)[j].get_u();
            point.serialize(&((*shuffledCommitments)[(i * n + j) * KEY_SIZE]));
            //            cout << "point" << i * n + j << ":";
            //            printKey(&((*shuffledCommitments)[(i * n + j) * KEY_SIZE]), 32);
            //            cout << endl;
        }
    }
    delete cipherTable;
    cipherTable = nullptr;
}

void shuffle_gen_with_regulation(char *commitments, int m, int n, char **shuffledCommitments,
                                 int *shuffledCommitmentsLen, char **proof, int *proofLen, int *permutation_in, char *R_in)
{
    if (!elgammal)
    {
        elgammal = (ElGammal *)create_pub_key_use_dero_H();
    }
    init();
    resetM_N(m, n);
    ZZ mod = G.get_mod();
    auto ciphers = new vector<vector<Cipher_elg> *>(getM());
    for (int i = 0; i < m; i++)
    {
        auto v = new vector<Cipher_elg>(n);
        for (int j = 0; j < n; j++)
        {
            CurvePoint point;
            point.deserialize(&commitments[(i * n + j) * KEY_SIZE]);
            (*v)[j] = Cipher_elg(Mod_p(point, mod));
        }
        (*ciphers)[i] = v;
    }
    auto cipherTable = new CipherTable(ciphers, m);
    cipherTable->set_dimentions(m, n);
    string shuffle_input(cipherTable->encode_all_ciphers());
    for (auto &cipher : *ciphers)
    {
        delete cipher;
    }
    delete ciphers;
    ciphers = nullptr;
    delete cipherTable;
    cipherTable = nullptr;
    char *input = (char *)shuffle_input.c_str();
    char *shuffled_ciphers;
    int shuffled_ciphers_len;
    vector<long> v;
    v.resize(m * n);
    for (int i = 0; i < v.size(); i++)
    {
        v[i] = permutation_in[i] + 1;
    }
    auto pi = new vector<vector<vector<long> *> *>(m);
    Permutation::perm_matrix(pi, v, n, m);
    auto R = new vector<vector<ZZ> *>(m);
    vector<ZZ> *r = 0;
    long i, j;
    for (i = 0; i < m; i++)
    {
        r = new vector<ZZ>(n);
        for (j = 0; j < n; j++)
        {
            r->at(j) = ZZFromBytes((const unsigned char *)&R_in[(i * n + j) * 32], 32);
        }
        R->at(i) = r;
    }
    void *cached_shuffle = shuffle_internal(elgammal, input, shuffle_input.size(), m * n,
                                            &shuffled_ciphers, &shuffled_ciphers_len, nullptr, nullptr, pi, R);
    prove(cached_shuffle, proof, proofLen, nullptr, nullptr);
    string inp(shuffled_ciphers, shuffled_ciphers_len);
    cipherTable = new CipherTable(inp, m, elgammal);
    ciphers = cipherTable->getCMatrix();
    m = cipherTable->rows();
    n = cipherTable->cols();
    *shuffledCommitmentsLen = m * n;
    *shuffledCommitments = new char[*shuffledCommitmentsLen * KEY_SIZE];
    for (int i = 0; i < m; i++)
    {
        auto v = ciphers->at(i);
        for (int j = 0; j < n; j++)
        {
            CurvePoint point;
            point = (*v)[j].get_u();
            point.serialize(&((*shuffledCommitments)[(i * n + j) * KEY_SIZE]));
            //            cout << "point" << i * n + j << ":";
            //            printKey(&((*shuffledCommitments)[(i * n + j) * KEY_SIZE]), 32);
            //            cout << endl;
        }
    }
    delete cipherTable;
    cipherTable = nullptr;
}

int shuffle_ver(char *commitments, int m, int n, char *shuffledCommitments, int shuffledCommitmentsLen, char *proof,
                int proofLen)
{
    init();
    resetM_N(m, n);
    ZZ mod = G.get_mod();
    auto ciphers = new vector<vector<Cipher_elg> *>(getM());
    for (int i = 0; i < m; i++)
    {
        auto v = new vector<Cipher_elg>(n);
        for (int j = 0; j < n; j++)
        {
            CurvePoint point;
            point.deserialize(&commitments[(i * n + j) * KEY_SIZE]);
            (*v)[j] = Cipher_elg(Mod_p(point, mod));
        }
        (*ciphers)[i] = v;
    }
    auto cipherTable = new CipherTable(ciphers, m);
    cipherTable->set_dimentions(m, n);
    string shuffle_input(cipherTable->encode_all_ciphers());
    for (auto &cipher : *ciphers)
    {
        delete cipher;
    }
    delete ciphers;
    ciphers = nullptr;
    delete cipherTable;
    cipherTable = nullptr;
    if (shuffledCommitmentsLen % m != 0)
    {
        return 0;
    }
    n = shuffledCommitmentsLen / m;
    ciphers = new vector<vector<Cipher_elg> *>(getM());
    for (int i = 0; i < m; i++)
    {
        auto v = new vector<Cipher_elg>(n);
        for (int j = 0; j < n; j++)
        {
            CurvePoint point;
            point.deserialize(&shuffledCommitments[(i * n + j) * KEY_SIZE]);
            (*v)[j] = Cipher_elg(Mod_p(point, mod));
            //            cout << "point" << i * n + j << ":";
            //            printKey(&shuffledCommitments[(i * n + j) * KEY_SIZE], 32);
            //            cout << endl;
        }
        (*ciphers)[i] = v;
    }
    cipherTable = new CipherTable(ciphers, m);
    cipherTable->set_dimentions(m, n);
    string shuffle_output(cipherTable->encode_all_ciphers());
    for (auto &cipher : *ciphers)
    {
        delete cipher;
    }
    delete ciphers;
    ciphers = nullptr;
    delete cipherTable;
    cipherTable = nullptr;
    int ret = verify(1, proof, proofLen, (char *)shuffle_input.c_str(), shuffle_input.size(),
                     (char *)shuffle_output.c_str(), shuffle_output.size(), nullptr, 0);
    return ret;
}

void deleteCharArray(char *ptr)
{
    delete[] ptr;
}

void deleteIntArray(int *ptr)
{
    delete[] ptr;
}