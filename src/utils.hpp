//
// Created by 69029 on 6/23/2021.
//
#pragma once

#include "my_hhash.h"
#include "config_pc.hpp"

extern double proving_time;
size_t next_pow2(size_t N);
void precompute_beta(vector<F> r,vector<F> &B);
vector<vector<F>> generate_tables();
vector<F> generate_randomness(int size);
vector<vector<F>> get_poly(int size);
vector<F> get_predicates(int size);
F evaluate_matrix(vector<vector<F>> M, vector<F> r1, vector<F> r2);
F evaluate_vector(vector<F> v,vector<F> r);
vector<F> prepare_matrix(vector<vector<F>> M, vector<F> r);
vector<F> convert2vector(vector<vector<F>> M);
vector<F> tensor2vector(vector<vector<vector<vector<F>>>> M);
vector<vector<vector<vector<F>>>> vector2tensor(vector<F> v,vector<vector<vector<vector<F>>>> M,int w);
vector<vector<F>> transpose(vector<vector<F>> M);
vector<vector<F>> convert2matrix(vector<F> arr, int d1, int d2);
vector<vector<F>> rotate(vector<vector<F>> M);
void initBetaTable(vector<F> &beta_g, u8 gLength, const vector<F>::const_iterator &r, const F &init);

void
initBetaTable(vector<F> &beta_g, int gLength, const vector<F>::const_iterator &r_0,
              const vector<F>::const_iterator &r_1, const F &alpha, const F &beta);

void fft(vector<F> &arr, int logn, bool flag);
//F getRootOfUnit(int n);
void phiGInit(vector<F> &phi_g, const vector<F>::const_iterator &rx, const F &scale, int n, bool isIFFT);
template <class T>
void myResize(vector<T> &vec, u64 sz) {
    if (vec.size() < sz) vec.resize(sz);
}

void compute_binary(vector<F> r, vector<F> &B);
F getRootOfUnity(int n);

void get_field_vector(vector<F> &h_f, vector<__hhash_digest> &h);
vector<F> compute_lagrange_coeff(F omega, F r, int degree);

void my_fft(vector<F> &arr, vector<F> &w, vector<u32> &rev, F ilen,  bool flag);
void compute_convolution(vector<vector<F>> Lv, vector<F> &B);
void _fft(F *arr, int logn, bool flag);

void init_matrix(F **&M, int rows, int cols);
void free_matrix(F **M,int rows);
F * init_vector( int rows);
void free_vector(F *M);
void __fft(F *&arr,  int logn, bool flag);
F F_eval_functionality( vector<vector<F>> &R, vector<F> &beta1 ,vector<F> &beta2, int _k);
F F_ip_functionality( vector<vector<F>> &R1, vector<vector<F>> &R2 , vector<F> &beta1 ,vector<F> &beta2, int _k, int k);
F F_ip_functionality2( vector<vector<F>> &R1, vector<vector<F>> &R2, vector<vector<F>> &R3, vector<F> &beta1 ,vector<F> &beta2, int _k, int k);
vector<vector<F>> F_quad_sumcheck_rest_functionality(F y, F b, vector<vector<F>> &_v1, vector<vector<F>> &_v2, vector<vector<F>> &_r1, vector<vector<F>> &_r2, int _k, int k,
                  double &pt, double &vt, double &ps);



void field_vector_serialize(vector<F> &v, vector<u64> &v_int);
void field_vector_deserialize(vector<u64> &v_int, vector<F> &v);
vector<int> convert2vector(vector<vector<int>> &M);
F _beta(int i, vector<F> r);
vector<F> convert_to_field(vector<int> &arr);
F beta_identity(vector<F> r1, vector<F> r2);
F get_offset_product(int size,int pos,vector<F> r);\
void prepare_witness_data(size_t size, vector<F> &witness, vector<F> &vL, vector<F> &vR, vector<F> &vO, int type=0);
vector<vector<F>> F_zero_check_rest_functionality(F y, F b, vector<vector<F>> &_v1, 
                                vector<vector<F>> &_v2, 
                                vector<vector<F>> &_v3, 
                                vector<F> &beta1, 
                                vector<F> beta2, 
                                vector<vector<F>> &_r1, 
                                vector<vector<F>> &_r2, 
                                int _k, int k,
                                double &pt, double &vt, double &ps);

vector<vector<F>> F_batch_quad_sumcheck_rest_functionality(F y, F b, vector<vector<F>> &_v1, 
                                                                     vector<vector<F>> &_v2, 
                                                                     vector<vector<F>> &_v3, 
                                                                     vector<vector<F>> &_v4, 
                                                                     vector<vector<F>> &_r1, 
                                                                     vector<vector<F>> &_r2, 
                                                                     int _k, int k,
                                                                    double &pt, double &vt, double &ps);

F sequence_eval(int size, vector<F> r1, vector<F> r2);
F betas_eval(int size, vector<F> r11, vector<F> r12, vector<F> r21, vector<F> r22);
F sparrow_V_check(vector<F> poly, int degree);
F evaluate_poly_extended(vector<F> poly, vector<F> poly_sum, F r, int c);