
#include "config_pc.hpp"
#include "constants.h"
#include <vector>
#include <math.h>
#include "utils.hpp"
#include "mimc.h"
#include <chrono>
#include <fcntl.h>
#include <omp.h>
#include <unistd.h>
#include <mutex>
#include "polynomial.h"
#include "coPIOP.h"
#include "coSumcheck.h"


void RS_fold(vector<F> &codeword, F a);
void setup(vector<vector<F>> &R_shares, int N, int M, int l, int k, int _k);
void encode_protocol_step2(vector<F> &row, vector<F> &rand, vector<F> &codeword);