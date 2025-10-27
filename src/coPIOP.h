#pragma once
#include "config_pc.hpp"
#include "constants.h"
#include <vector>
#include <math.h>
#include "utils.hpp"


struct gate{
    int id,id_right;
    vector<int> id_left;
    // type 0: Input
    // type 1: mul
    // type 2: add
    int type;
};


void generate_R1CS_matrixes(size_t size, int type= 0);
void prepare_data(size_t size, vector<F> &witness, vector<F> &vL, vector<F> &vR, vector<F> &vO);
void secret_share_proving_data(vector<F> &witness, 
                               vector<vector<F>> &tr, 
                               vector<vector<F>> &W, 
                               vector<vector<vector<F>>> &Tr, int k, int _k, int N);


void reduce_R1CS_matrixes(size_t size, vector<F> r, vector<F> &RA, vector<F> &RB, vector<F> &RC);
void compute_secret_shares(vector<F> &v, vector<vector<F>> &v_shares, int N, int _k, int k);





void prove_R1CS(size_t size, int N, int _k, int k);
void coPIOP_prove(size_t size, int N, int _k, int k, int cir_type=0);

void prove_R1CS_standard(size_t size);
void compute_beta_shares(vector<F> &shares, vector<F> r, int k, int N, int _k);