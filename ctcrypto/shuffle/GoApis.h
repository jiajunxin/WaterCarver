//
// Created by wyongcan on 2019/10/14.
//

#ifndef WATERCARVER_GOAPIS_H
#define WATERCARVER_GOAPIS_H
#ifdef __cplusplus
extern "C" {
#endif
void shuffle_gen(char *commitments, int m, int n, char **shuffledCommitments, int *shuffledCommitmentsLen,
                 int **permutation, int *permutationLen, char **proof, int *proofLen);
void shuffle_gen_with_regulation(char *commitments, int m, int n, char **shuffledCommitments,
                 int *shuffledCommitmentsLen, char **proof, int *proofLen, int *permutation_in, char *R_in);
int shuffle_ver(char *commitments, int m, int n, char *shuffledCommitments, int shuffledCommitmentsLen,
                 char *proof, int proofLen);
void deleteCharArray(char *ptr);
void deleteIntArray(int *ptr);
#ifdef __cplusplus
}
#endif
#endif //WATERCARVER_GOAPIS_H