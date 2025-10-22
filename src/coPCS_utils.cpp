
#include "coPCS_utils.h"

vector<vector<F>> global_poly;
int rate = 4;
int l = 500;

void setup(vector<vector<F>> &R_shares, int N, int M, int l, int k, int _k){
    vector<vector<F>> R(l);
    R_shares.resize(l);
    for(int i = 0; i < l; i++){
        R[i].resize(_k);
        R_shares[i].resize(N,0);
        for(int j = 0; j < _k; j++){
            R[i][j] = F(j*3122 + i);
        }
    }
    if(global_poly.size() != 0){
        for(int i = 0; i < l; i++){
            for(int j = 0; j < _k; j++){
                global_poly[j][i+M/k] = R[i][j];
            }
        }
    }
    
    for(int i = 0; i < l; i++){
        fft(R[i],(int)log2(_k),true);
        R[i].resize(2*N);
        fft(R[i],(int)log2(2*N),false);
        for(int j = 0; j < N; j++){
            R_shares[i][j] = R[i][2*j+1];
        }
    }
    
}


void encode_protocol_step2(vector<F> &row, vector<F> &rand, vector<F> &codeword){
    vector<F> buff(next_pow2(row.size() + rand.size()),0);
    for(int i = 0; i < row.size(); i++){
        buff[i] = row[i];
    }
    for(int i = 0; i < rand.size(); i++){
        buff[i+row.size()] = rand[i];
    }
    fft(buff,(int)log2(buff.size()),true);
    codeword.resize(rate*buff.size(),0);
    for(int i = 0; i < buff.size(); i++){
        codeword[i] = buff[i];
    }
    fft(codeword,(int)log2(codeword.size()),false);
}

void RS_fold(vector<F> &codeword, F a){
    int n = codeword.size();
    F two_inv = F(2).inv();
    vector<F> new_codeword(codeword.size()/2);
    F omega = getRootOfUnity((int)log2(codeword.size()));
    omega = omega.inv();
    F inv_omegas = F(1);
    for(int i = 0; i < new_codeword.size(); i++){
        new_codeword[i] = two_inv*((F(1)-a)*(codeword[i] + codeword[i+n/2])+ a*inv_omegas*(codeword[i] - codeword[i+n/2])); 
        inv_omegas = inv_omegas*omega;
    }
    codeword = new_codeword;
}





