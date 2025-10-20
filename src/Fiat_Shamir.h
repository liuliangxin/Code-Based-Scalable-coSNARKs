
#include "config_pc.hpp"
#include "utils.hpp"
#include "math.h"
#include "coPCS_utils.h"
#include <mpi.h>


F hash_to_field(vector<F> elements);
vector<vector<u32>> get_indexes(int l, int N, int M, int pos);
