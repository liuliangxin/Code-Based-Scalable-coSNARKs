#include "coPIOP.h"
#include "sparse_eval.hpp"
#include "config_pc.hpp"
#include "utils.hpp"
#include "math.h"
#include "coPCS_utils.h"
#include <mpi.h>


F F_ip(vector<F> &data, vector<F> &v1, vector<F> &v2, int k, int _k, int N);
F F_ip_prod(vector<F> &data1, vector<F> &data2, vector<F> &v1, vector<F> &v2, int k, int _k, int N);
quadratic_poly aggregate_quadratic_poly(quadratic_poly H, vector<F> &v, int k, int _k, int N);
cubic_poly aggregate_cubic_poly(cubic_poly H, vector<F> &v, int k, int _k, int N);

vector<pair<F,vector<F>>> F_zero_check_rest(F v1, F v2, F v3, F h1, F h2, 
                                            vector<F> &beta1, vector<F> &beta2, 
                                            F b, F y, int k, int _k, int N);
quadratic_poly aggregate_quadratic_poly(quadratic_poly H, int k, int _k, int N);

vector<pair<F,vector<F>>> F_batch_sumcheck_rest(F v1, F v2, F v3, F v4, F h1, F h2, 
                                            F b, F y, int k, int _k, int N);

F distributed_eval(vector<F> &poly, vector<F> &beta1, vector<F> &beta2, int N);
vector<F> batch_distributed_eval(vector<vector<F>> &poly, vector<F> &beta1, vector<F> &beta2, int N);
void distribute_index(int N, int M,vector<sparse_eval_data> &index);
void distribute_proving_data(vector<F> &vL, vector<F> &vR, vector<F> &vO, vector<F> &w, int N, int M, int _k, int k);
void setup_randomness(vector<F> &R, vector<F> &_R, int N, int _k, int k);
void compute_secret_shares(vector<F> &v, vector<vector<F>> &v_shares, int N, int k, int _k, bool privacy_preserving);