#include "config_pc.hpp"
#include "constants.h"
#include <vector>
#include <math.h>
#include "utils.hpp"
#include "merkle_tree.h"
#include "polynomial.h"
#include <mpi.h>
#include "Fiat_Shamir.h"
#include "sparse_eval.hpp"


vector<pair<F,vector<F>>> _quadratic_sumcheck(F y, vector<F> &v1, vector<F> &v2, int N);
vector<pair<F,vector<F>>> _cubic_sumcheck(F y, vector<F> &v1, vector<F> &v2, vector<F> &v3, vector<F> &v, int N);

pair<F,vector<vector<F>>> prove_product(vector<vector<F>> &input, vector<F> &output, F y, vector<F> r, int N);
void compute_R1CS_betas(vector<F> r1, vector<F> r2, vector<sparse_eval_data> &data, vector<vector<F>> &beta1, vector<vector<F>> &beta2, int logm, int logn, int N);
void _reduce_R1CS_matrixes(size_t size, vector<F> r, vector<F> &RA, vector<F> &RB, vector<F> &RC, int N);
pair<F,vector<F>> _prove_sparse_eval(F y, F a, F b, F c, 
                        vector<vector<F>> &beta1, vector<vector<F>> &beta2, vector<sparse_eval_data> &data, 
                        vector<F> r1, vector<F> r2, 
                        int N);
void secret_share_vector(vector<F> &v, int _k, int k, int N);
quadratic_poly aggregate_poly(quadratic_poly H, int N);