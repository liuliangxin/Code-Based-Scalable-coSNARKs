#include "config_pc.hpp"
#include "constants.h"
#include <vector>
#include <math.h>
#include "utils.hpp"
#include "merkle_tree.h"
#include "polynomial.h"


vector<std::pair<F,vector<F>>> _zero_check_sumcheck(F y, vector<F> &v1, 
                                vector<F> &v2, vector<F> &v3, vector<F> &R1, vector<F> &R2, 
                                vector<F> r, int N, int _k, int k, double &pt, double &vt, double &ps, double &cm);

vector<std::pair<F,vector<F>>> _quadratic_batch_sumcheck(F y, vector<F> &v1, 
                                vector<F> &v2, vector<F> &v3, vector<F> &v4, vector<F> &R1, vector<F> &R2, 
                                int N, int _k, int k, double &pt, double &vt, double &ps, double &cm);

vector<std::pair<F,vector<F>>> _quadratic_cosumcheck(F y, vector<F> &v1, vector<F> &v2, int N, int _k, int k, double &pt, double &vt, double &ps, double &cm);