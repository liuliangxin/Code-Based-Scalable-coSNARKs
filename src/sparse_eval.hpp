#pragma once
#include "config_pc.hpp"
#include "polynomial.h"


struct mul_tree_proof{
	F initial_randomness;
	// If we have a single product
	size_t size;
	F in1,in2;
	F out_eval;
	vector<struct proof> proofs;
	vector<F> output;
	vector<F> final_r;
	vector<F> global_randomness,individual_randomness;
	vector<F> partial_eval;
	F final_eval;
};
struct proof{
	int type;
	vector<vector<F>> randomness;
	vector<quadratic_poly> q_poly;
	vector<cubic_poly> c_poly;
	vector<F> output;
	vector<F> vr;
	vector<F> gr;
	vector<F> liu_sum;
	vector<vector<F>> sig;
	vector<vector<F>> final_claims_v;
	F divident,divisor,quotient,remainder;
	// Witnesses to make hash calclulation circuit less deep
	vector<vector<vector<F>>> w_hashes;
	vector<F> r,individual_sums;
	vector<vector<F>> Partial_sums;
	vector<quadratic_poly> q_poly1;
	vector<quadratic_poly> q_poly2;
	F final_rand;
	F final_sum;
	int K;

};

struct sparse_eval_data{
    vector<int> RD1,RD2,WR1,WR2;
    vector<int> IDX1,IDX2;
    vector<int> FINAL_FR1,FINAL_FR2;
};



void prove_sparse_eval_bit(vector<F> r, F y, vector<vector<short>> &bits, vector<vector<int>> &idx, 
                                int logm, int logn, int N, 
                                double &pt, double &vt, double &ps);

void prepare_data(vector<vector<pair<int,int>>> &M, int logm, int logn, sparse_eval_data &data);

void prove_sparse_eval(F y, F a, F b, F c, vector<F> &beta1, vector<F> &beta2, vector<sparse_eval_data> &data, double &pt, double &ps, double &vt);
void prepare_R1CS_data(vector<vector<pair<int,int>>> &A, vector<vector<pair<int,int>>> &B, vector<vector<pair<int,int>>> &C, int logm, int logn, vector<sparse_eval_data> &data);

vector<pair<F,vector<F>>> cubic_sumcheck(F y, vector<F> &v1, vector<F> &v2, vector<F> &v3,F previous_r, double &vt, double &ps);

vector<pair<F,vector<F>>> zerocheck_sumcheck(F y, vector<F> &v1, vector<F> &v2, vector<F> &v3, vector<F> &v4,F previous_r, double &vt, double &ps);
vector<pair<F,vector<F>>> quadratic_sumcheck(F y, vector<F> &v1, vector<F> &v2,F previous_r, double &vt, double &ps);
pair<F,vector<F>> prove_multiplication_tree_new(vector<vector<F>> &input, vector<F> &output, F previous_r, F y, vector<F> r, double &vt, double &ps);