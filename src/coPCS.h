#include "MPI_utils.hpp"
#include "config_pc.hpp"
#include "utils.hpp"
#include "math.h"
#include "coPCS_utils.h"
#include <mpi.h>


struct MT{
    vector<vector<_hash>> Base_MT;
    vector<vector<_hash>> Root_MT;
};

typedef struct MT MT;

void encode(vector<F> &codeword, vector<F> &row_data, vector<vector<F>> &data, vector<F> &R_shares, int l, int k, int _k, int M, int N);

void commit(vector<F> &codeword, vector<F> &row_data, vector<F> &R_shares, MT &Com, int l, int k, int _k, int M, int N);
void plaintext_commit(vector<F> &data, vector<F> &codeword ,vector<F> &row_data, MT &Com, int k, int N);

void dummy_setup(vector<F> &R_shares, vector<vector<F>> &mask_shares, int N, int M, int k, int _k, int l);
void prepare_mask_shares(vector<vector<F>> &mask_shares, vector<vector<F>> &mask_data, vector<vector<F>> &C_mask, vector<MT> &Com_mask, int N, int M, int k, int _k, int l);
void open_zk(vector<F> &codeword, vector<vector<F>> &mask_codeword, 
             vector<F> &row_data, vector<vector<F>> &mask_data, 
             MT &Com, vector<MT> Mask_Com, 
             vector<F> r, F y, int l, int k, int _k, int M, int N, double &ps, double &vt);

void open_plaintext(vector<F> &codeword, vector<F> &row_data,
                    vector<F> &v1, vector<F> &v2, MT &Com, F y, int l, int k, int N, double &ps, double &vt, bool secret_shared,bool verify=true);

void commit_randomness(vector<F> R, vector<F> _R, vector<F> &codeword, vector<F> &_codeword, MT &CR, MT &_CR, int N);
void distributed_MT(vector<F> &data, MT &Com, int N);
void commit(vector<F> &codeword, vector<F> &row_data, vector<F> &W_shares, vector<F> &R_shares, MT &Com, int l, int k, int _k, int M, int N);