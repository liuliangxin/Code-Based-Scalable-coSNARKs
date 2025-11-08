#include "sparse_eval.hpp"
#include "config_pc.hpp"
#include "constants.h"
#include <vector>
#include <math.h>
#include "utils.hpp"
#include "merkle_tree.h"
#include "timer.hpp"
#include "Distributed_Sumcheck.h"
vector<int> real_idx_dim;
extern timer vt;


vector<pair<F,vector<F>>> batch_cubic_sumcheck(vector<F> &v1,vector<F> &v2, vector<F> &v3, vector<F> &v4, F y, F a){
    int rounds = (int)log2(v1.size());
    vector<F> r;
    for(int i = 0; i < rounds; i++){
        int L = 1ULL<<(rounds-1-i);
        quadratic_poly l1,l2;
        cubic_poly p = cubic_poly(0,0,0,0);
        for(int j = 0; j  < L; j++){
            l1 = linear_poly(v1[2*j+1]-v1[2*j],v1[2*j])*linear_poly(v2[2*j+1]-v2[2*j],v2[2*j]);
            l1.b = l1.b + a*(v3[2*j+1]-v3[2*j]);
            l1.c = l1.c + a*(v3[2*j]);
            p = p + l1*linear_poly(v4[2*j+1]-v4[2*j],v4[2*j]);
        }
        if(p.eval(0) + p.eval(1) != y){
            printf("Error in round %d of batch sumckeck\n",i);
            exit(-1);   
        }
        F rand = F::_random();
        r.push_back(rand);
        y = p.eval(rand);
        for(int j = 0; j < L; j++){
            v1[j] = rand*(v1[2*j+1]-v1[2*j]) + v1[2*j];
            v2[j] = rand*(v2[2*j+1]-v2[2*j]) + v2[2*j];
            v3[j] = rand*(v3[2*j+1]-v3[2*j]) + v3[2*j];
            v4[j] = rand*(v4[2*j+1]-v4[2*j]) + v4[2*j];
        }
    }
    return {make_pair(v1[0],r),make_pair(v2[0],r),make_pair(v3[0],r),make_pair(v4[0],r)};
}
pair<F,vector<F>> batch_sumcheck(F y, vector<F> &beta,vector<vector<short>> &_bits, vector<F> r, vector<F> neg_r){
    r.resize(next_pow2(r.size()),F(1));

    int l = next_pow2(_bits[0].size());
    vector<F> bits(beta.size(),F(0));
    for(int i = 0; i < _bits.size(); i++){
        for(int j = 0; j < _bits[0].size(); j++){
            bits[i*l+j] = _bits[i][j];
        }
        for(int j = _bits[0].size(); j < l; j++){
            bits[i*l+j] = F(1);
        }
    }
    neg_r.resize(next_pow2(neg_r.size()),F(0));
    int rounds = (int)log2(beta.size());
    vector<F> R(beta.size());
    for(int i = 0; i  < R.size()/r.size(); i++){
        for(int j = 0; j < r.size(); j++){
            R[i*r.size() + j] = r[j];
        }
    }
    for(int i = _bits.size()*r.size(); i < R.size(); i++){
        R[i] = 1;
    }

    vector<F> _r;
    for(int i = 0; i < rounds; i++){
        cubic_poly poly = cubic_poly(F_ZERO,F_ZERO,F_ZERO,F_ZERO);
		linear_poly one = linear_poly(-F_ONE,-F_ONE);
        linear_poly l1,l2,l3,l4,l5;
        int L = 1ULL<<(rounds-1-i);
        for(int j = 0; j  < L; j++){
            l1 = linear_poly(bits[2*j+1]-bits[2*j],bits[2*j]);
            l4 = linear_poly(-bits[2*j+1]+bits[2*j],F(1) - bits[2*j]);
            l2 = linear_poly(beta[2*j+1]-beta[2*j],beta[2*j]);
            l3 = linear_poly(R[2*j+1]-R[2*j],R[2*j]);
            l5 = linear_poly(-R[2*j+1]+R[2*j],F(1) -R[2*j]);
            poly = poly + (l1*l3 + l4*l5)*l2; 
        }
        if(poly.eval(F(0)) + poly.eval(F(1)) != y){
            printf("Error in round %d of batch sumckeck\n",i);
            exit(-1);
        }
        F rand = F::_random();
        y = poly.eval(rand);
        _r.push_back(rand);
        for(int j = 0; j  < L; j++){
            bits[j] = rand*(bits[2*j+1]-bits[2*j]) + bits[2*j];
            beta[j] = rand*(beta[2*j+1]-beta[2*j]) + beta[2*j];
            R[j] = rand*(R[2*j+1]-R[2*j]) + R[2*j];
        }
    }
    return make_pair(bits[0],_r);
}

pair<F,vector<F>> sumcheck(F y, vector<F> &v1, double &vt, double &ps){
	struct proof Pr;
	//vector<F> r = generate_randomness(int(log2(v1.size())));
	int rounds = int(log2(v1.size()));
	F rand;
	vector<F> r;
	for(int i = 0; i < rounds; i++){
		linear_poly poly = linear_poly(F_ZERO,F_ZERO);
		linear_poly l1,l2,l3;
			
		int L = 1 << (rounds -1- i);
		for(int j = 0; j < L; j++){
			l1 = linear_poly(v1[2*j+1] - v1[2*j],v1[2*j]);
			poly = poly + l1;			
		}

		vector<F> input;
		
		clock_t s,e;
		s = clock();
		if(poly.eval(0) + poly.eval(1) != y){
            printf("> Error single sumcheck %d\n",i);
            //exit(-1);
        }
        rand = F::_random();//mimc_hash(rand,poly.a);
		rand = F::_random();//mimc_hash(rand,poly.d);
		r.push_back(rand);
        y = poly.eval(rand);
        e = clock();
		ps += 2*sizeof(F)/1024.0;
		vt += (double)(e-s)/(double)CLOCKS_PER_SEC;
		for(int j = 0; j < L; j++){
			v1[j] = rand*(v1[2*j+1] - v1[2*j]) + v1[2*j];
		}
	}
    return make_pair(v1[0],r);
}


vector<pair<F,vector<F>>> quadratic_sumcheck(F y, vector<F> &v1, vector<F> &v2,F previous_r){
	struct proof Pr;
	//vector<F> r = generate_randomness(int(log2(v1.size())));
	int rounds = int(log2(v1.size()));
	F rand = previous_r;
	vector<F> r;
	for(int i = 0; i < rounds; i++){
		quadratic_poly poly = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
			linear_poly l1,l2;
			
			int L = 1 << (rounds -1- i);
			for(int j = 0; j < L; j++){
				l1 = linear_poly(v1[2*j+1] - v1[2*j],v1[2*j]);
				l2 = linear_poly(v2[2*j+1] - v2[2*j],v2[2*j]);
				poly = poly + (l1*l2);
				
			}

		vector<F> input;
		
		clock_t s,e;
		s = clock();
        vt.start();
		
		if(poly.eval(0)+ poly.eval(1) != y){
            printf("Error in sumcheck round %d\n",i);
            exit(-1);
        }
        rand = F::_random();//mimc_hash(rand,poly.a);
		rand = F::_random();//mimc_hash(rand,poly.b);
		rand = F::_random();///mimc_hash(rand,poly.c);
		rand = F::_random();//mimc_hash(rand,poly.d);
		e = clock();
		//ps += 5*sizeof(F)/1024.0;
		y = poly.eval(rand);
        vt.end();
		r.push_back(rand);
		
        //vt += (double)(e-s)/(double)CLOCKS_PER_SEC;

		for(int j = 0; j < L; j++){
            v1[j] = rand*(v1[2*j+1]-v1[2*j]) + v1[2*j];
            v2[j] = rand*(v2[2*j+1]-v2[2*j]) + v2[2*j];
        }
		//vector<vector<F>> temp = mimc_multihash3(input);
		//Pr.w_hashes.push_back(temp);
		
		//rand = temp[temp.size()-1][temp[0].size()-1];
		//rand = mimc_multihash(input);
	}	
	
    return {make_pair(v1[0] ,r),make_pair(v2[0] ,r)};
}


vector<pair<F,vector<F>>> zerocheck_sumcheck(F y, vector<F> &v1, vector<F> &v2, vector<F> &v3, vector<F> &v4,F previous_r, double &vt, double &ps){
	struct proof Pr;
	//vector<F> r = generate_randomness(int(log2(v1.size())));
	int rounds = int(log2(v1.size()));
	vector<cubic_poly> p;
	F rand = previous_r;
	vector<F> r;
	for(int i = 0; i < rounds; i++){
		cubic_poly poly = cubic_poly(F_ZERO,F_ZERO,F_ZERO,F_ZERO);
			cubic_poly temp_poly = cubic_poly(F_ZERO,F_ZERO,F_ZERO,F_ZERO);
			linear_poly l1,l2,l3;
            quadratic_poly l4 = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
			
			int L = 1 << (rounds -1- i);
			for(int j = 0; j < L; j++){
				l1 = linear_poly(v1[2*j+1] - v1[2*j],v1[2*j]);
				l2 = linear_poly(v2[2*j+1] - v2[2*j],v2[2*j]);
				l3 = linear_poly(v3[2*j+1] - v3[2*j],v3[2*j]);
                l4 = quadratic_poly(F_ZERO,-v4[2*j+1] + v4[2*j],-v4[2*j]);
				poly = poly + ((l2*l3 + l4)*l1);
			}

		vector<F> input;
		
		clock_t s,e;
		s = clock();
		if(poly.eval(0)+ poly.eval(1) != y){
            printf("Error in sumcheck round %d\n",i);
            exit(-1);
        }
        rand = F::_random();//mimc_hash(rand,poly.a);
		rand = F::_random();//mimc_hash(rand,poly.b);
		rand = F::_random();///mimc_hash(rand,poly.c);
		rand = F::_random();//mimc_hash(rand,poly.d);
		e = clock();
		ps += 5*sizeof(F)/1024.0;
		y = poly.eval(rand);
        r.push_back(rand);
		
        vt += (double)(e-s)/(double)CLOCKS_PER_SEC;

		for(int j = 0; j < L; j++){
            v1[j] = rand*(v1[2*j+1]-v1[2*j]) + v1[2*j];
            v2[j] = rand*(v2[2*j+1]-v2[2*j]) + v2[2*j];
            v3[j] = rand*(v3[2*j+1]-v3[2*j]) + v3[2*j];
            v4[j] = rand*(v4[2*j+1]-v4[2*j]) + v4[2*j];
        }
		//vector<vector<F>> temp = mimc_multihash3(input);
		//Pr.w_hashes.push_back(temp);
		
		//rand = temp[temp.size()-1][temp[0].size()-1];
		//rand = mimc_multihash(input);
		p.push_back(poly);
	}
	
    return {make_pair(v1[0],r),make_pair(v2[0],r),make_pair(v3[0],r),make_pair(v4[0],r)};
}

vector<pair<F,vector<F>>> cubic_sumcheck(F y, vector<F> &v1, vector<F> &v2, vector<F> &v3,F previous_r){
	struct proof Pr;
	//vector<F> r = generate_randomness(int(log2(v1.size())));
	int rounds = int(log2(v1.size()));
	vector<cubic_poly> p;
	F rand = previous_r;
	vector<F> r;
	for(int i = 0; i < rounds; i++){
		cubic_poly poly = cubic_poly(F_ZERO,F_ZERO,F_ZERO,F_ZERO);
			cubic_poly temp_poly = cubic_poly(F_ZERO,F_ZERO,F_ZERO,F_ZERO);
			linear_poly l1,l2,l3;
			
			int L = 1 << (rounds -1- i);
			for(int j = 0; j < L; j++){
				l1 = linear_poly(v1[2*j+1] - v1[2*j],v1[2*j]);
				l2 = linear_poly(v2[2*j+1] - v2[2*j],v2[2*j]);
				l3 = linear_poly(v3[2*j+1] - v3[2*j],v3[2*j]);
				poly = poly + (l1*l2*l3);
				
			}

		vector<F> input;
		
		clock_t s,e;
		s = clock();
        vt.start();
		if(poly.eval(0)+ poly.eval(1) != y){
            printf("Error in sumcheck round %d\n",i);
            //exit(-1);
        }
        rand = F::_random();//mimc_hash(rand,poly.a);
		rand = F::_random();//mimc_hash(rand,poly.b);
		rand = F::_random();///mimc_hash(rand,poly.c);
		rand = F::_random();//mimc_hash(rand,poly.d);
		e = clock();
		//ps += 5*sizeof(F)/1024.0;
		y = poly.eval(rand);
        vt.end();
		
        r.push_back(rand);
		
        //vt += (double)(e-s)/(double)CLOCKS_PER_SEC;

		for(int j = 0; j < L; j++){
            v1[j] = rand*(v1[2*j+1]-v1[2*j]) + v1[2*j];
            v2[j] = rand*(v2[2*j+1]-v2[2*j]) + v2[2*j];
            v3[j] = rand*(v3[2*j+1]-v3[2*j]) + v3[2*j];
        }
		//vector<vector<F>> temp = mimc_multihash3(input);
		//Pr.w_hashes.push_back(temp);
		
		//rand = temp[temp.size()-1][temp[0].size()-1];
		//rand = mimc_multihash(input);
		p.push_back(poly);
	}

	
    	
	
    return {make_pair(v1[0],r),make_pair(v2[0],r),make_pair(v3[0],r)};
}

pair<F,vector<F>> cubic_sumcheck_prod(F y, vector<F> &v1, vector<F> &v2, vector<F> &v3,F previous_r, double &vt, double &ps){
	struct proof Pr;
	//vector<F> r = generate_randomness(int(log2(v1.size())));
	int rounds = int(log2(v1.size()));
	vector<cubic_poly> p;
	F rand = previous_r;
	vector<F> r;
	for(int i = 0; i < rounds; i++){
		cubic_poly poly = cubic_poly(F_ZERO,F_ZERO,F_ZERO,F_ZERO);
			cubic_poly temp_poly = cubic_poly(F_ZERO,F_ZERO,F_ZERO,F_ZERO);
			linear_poly l1,l2,l3;
			
			int L = 1 << (rounds -1- i);
			for(int j = 0; j < L; j++){
				l1 = linear_poly(v1[2*j+1] - v1[2*j],v1[2*j]);
				l2 = linear_poly(v2[2*j+1] - v2[2*j],v2[2*j]);
				l3 = linear_poly(v3[2*j+1] - v3[2*j],v3[2*j]);
				poly = poly + (l1*l2*l3);
				
			}

		vector<F> input;
		
		clock_t s,e;
		s = clock();
		if(poly.eval(0)+ poly.eval(1) != y){
            printf("Error in sumcheck round %d\n",i);
            exit(-1);
        }
        rand = F::_random();//mimc_hash(rand,poly.a);
		rand = F::_random();//mimc_hash(rand,poly.b);
		rand = F::_random();///mimc_hash(rand,poly.c);
		rand = F::_random();//mimc_hash(rand,poly.d);
		e = clock();
		ps += 5*sizeof(F)/1024.0;
		y = poly.eval(rand);
        r.push_back(rand);
		
        vt += (double)(e-s)/(double)CLOCKS_PER_SEC;

		for(int j = 0; j < L; j++){
            v1[j] = rand*(v1[2*j+1]-v1[2*j]) + v1[2*j];
            v2[j] = rand*(v2[2*j+1]-v2[2*j]) + v2[2*j];
            v3[j] = rand*(v3[2*j+1]-v3[2*j]) + v3[2*j];
        }
		//vector<vector<F>> temp = mimc_multihash3(input);
		//Pr.w_hashes.push_back(temp);
		
		//rand = temp[temp.size()-1][temp[0].size()-1];
		//rand = mimc_multihash(input);
		p.push_back(poly);
	}

	clock_t s,e;
	s = clock();
	rand = F::_random();//mimc_hash(rand,v1[0]);
	rand = F::_random();//mimc_hash(rand,v2[0]);
    r.insert(r.begin(),rand);
	//rand = mimc_hash(rand,v3[0]);
	e = clock();
	ps += 3*sizeof(F)/1024.0;
	vt += (double)(e-s)/(double)CLOCKS_PER_SEC;
		
	
    return make_pair((F(1)-rand)*v1[0] + rand*v2[0],r);
}





pair<F,vector<F>> prove_multiplication_tree_new(vector<vector<F>> &input, vector<F> &output, F previous_r, F y, vector<F> r){
	double vt,ps;
    int vectors = input.size();
	int depth = (int)log2(input[0].size());
	int size = input[0].size();
	for(int i = 0; i < input.size(); i++){
		if(input[i].size() != size){
			printf("Error in mul tree sumcheck, no equal size vectors %d,%d\n",input[i].size(),size);
			exit(-1);
		}
	}

	if(1<<depth != size){
		depth++;
		size = 1<<depth;
		for(int i = 0; i < input.size(); i++){
			input[i].resize(1<<depth,F(1));
		}
	}

	if(vectors != 1<<((int)log2(vectors))){
		vectors = 1<<((int)log2(vectors)+1);
		int old_vector_size = input.size();
		vector<F> temp_vector(1<<depth,F(0));
		for(int i = 0; i < vectors-old_vector_size; i++){
			input.push_back(temp_vector);
		}
	}
	
	// Initialize total input
	int total_input_size = vectors*size;
	
	//printf("total input %d\n",total_input_size );
	vector<F> total_input(total_input_size);
	int counter = 0;
	for(int j = 0; j < input.size(); j++){
		for(int i = 0; i < input[0].size(); i++){
			total_input[counter] = input[j][i];
			counter++;
		}
	}	
	
    vector<vector<F>> transcript(depth);
	vector<vector<F>> in1(depth),in2(depth);
	for(int i = 0; i < depth; i++){
		transcript[i].resize(total_input_size/(1<<(i+1)));
		in1[i].resize(total_input_size/(1<<(i+1)));
		in2[i].resize(total_input_size/(1<<(i+1)));
	}
	
	counter = 0;
	for(int i = 0; i < total_input_size/2; i++){
		transcript[0][counter] = total_input[2*i]*total_input[2*i+1];
		in1[0][counter] = total_input[2*i];
		in2[0][counter] = total_input[2*i+1];
		counter++;
		
	}
    
	int len = total_input_size/2;
	for(int i = 1; i < transcript.size(); i++){
		counter = 0;
		for(int j = 0; j < len/2; j++){
			transcript[i][counter] = transcript[i-1][2*j]*transcript[i-1][2*j + 1];
			in1[i][counter] = transcript[i-1][2*j];
			in2[i][counter] = transcript[i-1][2*j + 1];
			counter++;
		}
		
		len = len/2;
	}

	//printf("Final prod len : %d\n",transcript[depth-1].size());
		
		F sum = y;//evaluate_vector(transcript[depth-1],r);
        
        if(r.size() == 0){
            for(int i = 0; i < (int)log2(transcript[depth-1].size()); i++){
                r.push_back(F::_random());
            }
            sum = evaluate_vector(transcript[depth-1],r);
        }
        proof P;
		vector<F> beta;
            output = transcript[depth-1];
        //precompute_beta(r,beta);
		pair<F,vector<F>> claim;
        for(int i = depth-1; i >= 0; i--){
			vector<F> beta;
			precompute_beta(r,beta);
            claim = cubic_sumcheck_prod(sum,in1[i], in2[i],beta,  previous_r, vt,ps);
			
            r = claim.second;
			sum = claim.first;
		}
		return make_pair(sum,r);
}

void compute_betas(vector<F> r, vector<vector<int>> &idx, int logm, int logn, int N, vector<F> &beta, double &pt){
    beta.resize(next_pow2(idx.size()),F(0));
    vector<F> r1,r2,r3,r4;
    vector<F> beta1,beta2,beta3,beta4;

    for(int i = 0; i < logm/2; i++){
        r1.push_back(r[i]);
    }
    for(int i = logm/2; i < logm; i++){
        r2.push_back(r[i]);
    }
    for(int i = logm; i < logm + (logn/2); i++){
        r3.push_back(r[i]);
    }
    for(int i = logm + (logn/2); i < logn+logm; i++){
        r4.push_back(r[i]);
    }


    clock_t t1 = clock();
    precompute_beta(r1,beta1);precompute_beta(r2,beta2);precompute_beta(r3,beta3);precompute_beta(r4,beta4);
    clock_t t2 = clock();
    pt += (double)(N*(t2-t1))/(double)CLOCKS_PER_SEC;
    for(int i = 0; i < idx.size(); i++){
        beta[i] = beta1[idx[i][0]]*beta2[idx[i][1]]*beta3[idx[i][2]]*beta4[idx[i][3]];
    }
}


void prove_sparse_eval_bit(vector<F> r, F y, vector<vector<short>> &bits, vector<vector<int>> &idx, 
                                int logm, int logn, int N, 
                                double &pt, double &vt, double &ps){
    
    clock_t t1 = clock();
    vector<vector<F>> input(bits.size());
    vector<F> neg_r(r.size()); 
    for(int i = 0; i < neg_r.size(); i++){
        neg_r[i] = F(1) - r[i];
    }
    int len = next_pow2(bits[0].size());
    for(int i = 0; i  < bits.size(); i++){
        input[i].resize(len,F(1));
        for(int j = 0; j < bits[i].size(); j++){
            if(bits[i][j]){
                input[i][j] = r[j];
            }else{
                input[i][j] = neg_r[j];
            }
        }
    }
    len = input.size();
    vector<F> pad(next_pow2(r.size()),0);
    for(int i = len; i < next_pow2(len); i++){
        input.push_back(pad);    
    }
    
    F rand = F::_random();
    vector<F> beta;
    
    compute_betas(r, idx, logm, logn, N, beta, pt);
    pair<F,vector<F>> claim =  sumcheck(y, beta,  vt, ps);
    vector<F> out;
    
    claim = prove_multiplication_tree_new(input,out,rand,claim.first,claim.second);
    printf("OK\n");
    beta.clear();precompute_beta(claim.second,beta);
    batch_sumcheck(claim.first, beta, bits, r,  neg_r);
    clock_t t2 = clock();
    pt += (double)(t2-t1)/(double)CLOCKS_PER_SEC;
}




void prepare_data(vector<vector<pair<int,int>>> &M, int logm, int logn, sparse_eval_data &data){
    int size = 0;
    for(int i = 0; i < M.size(); i++){
        size += M[i].size();
    }
    
    data.RD1.resize(next_pow2(size),0);data.RD2.resize(next_pow2(size),0);data.WR1.resize(next_pow2(size),0);data.WR2.resize(next_pow2(size),0);
    data.IDX1.resize(next_pow2(size),0);data.IDX2.resize(next_pow2(size),0);
    real_idx_dim.push_back(size);
    vector<int> r_count(1ULL<<logm,0);
    int ctr = 0;
    for(int i = 0; i < M.size(); i++){
        for(int j = 0; j < M[i].size(); j++){
            data.RD1[ctr] = r_count[M[i][j].second];
            data.WR1[ctr] = r_count[M[i][j].second] + (1);
            data.IDX1[ctr] = M[i][j].second;
            ctr++;
            r_count[M[i][j].second]++;
        }
    }
    for(int i = ctr; i < data.IDX1.size(); i++){
            data.RD1[i] = r_count[0];
            data.WR1[i] = r_count[0] + (1);
            data.IDX1[i] = 0;
            r_count[0]++;    
    }
    data.FINAL_FR1 = r_count;
    r_count.clear();r_count.resize(1ULL<<logn,0);
    ctr = 0;
    for(int i = 0; i < M.size(); i++){
        for(int j = 0; j < M[i].size(); j++){
            data.RD2[ctr] = r_count[M[i][j].first];
            data.WR2[ctr] = r_count[M[i][j].first] + (1);
            data.IDX2[ctr] = M[i][j].first;
            ctr++;
            r_count[M[i][j].first]++;
        }
    }
    for(int i = ctr; i < data.IDX2.size(); i++){
        data.RD2[i] = r_count[0];
        data.WR2[i] = r_count[0] + (1);
        data.IDX2[i] = 0;
        r_count[0]++;    
    }

    data.FINAL_FR2 = r_count;


}

void prepare_R1CS_data(vector<vector<pair<int,int>>> &A, vector<vector<pair<int,int>>> &B, vector<vector<pair<int,int>>> &C, int logm, int logn, vector<sparse_eval_data> &data){
    data.resize(3);
    prepare_data(A,  logm, logn, data[0]);   
    prepare_data(B,  logm, logn, data[1]);   
    prepare_data(C,  logm, logn, data[2]);   
}

vector<pair<F,vector<F>>> compute_eval_claims(vector<F> r, vector<F> &beta, vector<vector<int>> RD, vector<vector<int>> IDX, vector<F> challenges,F y){
    
    vector<F> B,_r = r;
    for(int i = 0; i < (int)log2(next_pow2(IDX.size())); i++){
         _r.pop_back();
    }
     _r.pop_back();
    
    precompute_beta(_r,B);
    
    vector<F> y1(IDX.size(),F(0)),y2(IDX.size(),F(0)),y3(IDX.size(),F(0));
    vector<F> _y(IDX.size(),F(0));
    for(int j = 0; j < RD.size(); j++){
        for(int i = 0; i < RD[j].size(); i++){
            y1[j] += B[i]*beta[IDX[j][i]];
            y2[j] += B[i]*F(RD[j][i]);
            y3[j] += B[i]*F(IDX[j][i]);
            _y[j] += B[i];
        }
    }
    F yL = (F(1)-r[r.size()-3])*(challenges[0]*y1[0] + challenges[1]*y2[0] + challenges[2]*y3[0] + F(1)) + 
            r[r.size()-3]*(challenges[0]*y1[0] + challenges[1]*(y2[0]+_y[0]) + challenges[2]*y3[0] + F(1));

    F yM = (F(1)-r[r.size()-3])*(challenges[0]*y1[1] + challenges[1]*y2[1] + challenges[2]*y3[1] + F(1)) + 
            r[r.size()-3]*(challenges[0]*y1[1] + challenges[1]*(y2[1]+_y[1]) + challenges[2]*y3[1] + F(1));

   F yR = (F(1)-r[r.size()-3])*(challenges[0]*y1[2] + challenges[1]*y2[2] + challenges[2]*y3[2] + F(1)) + 
            r[r.size()-3]*(challenges[0]*y1[2] + challenges[1]*(y2[2]+_y[2]) + challenges[2]*y3[2] + F(1));

    if(y != (F(1)-r[r.size()-2])*(F(1)-r[r.size()-1])*yL + (r[r.size()-2])*(F(1)-r[r.size()-1])*yM + (F(1) - r[r.size()-2])*(r[r.size()-1])*yR){
        printf("Error in claim validation\n");
        exit(-1);
    }
    return {make_pair(y1[0],_r),make_pair(y2[0],_r),make_pair(y3[0],_r),
            make_pair(y1[1],_r),make_pair(y2[1],_r),make_pair(y3[1],_r),
            make_pair(y1[2],_r),make_pair(y2[2],_r),make_pair(y3[2],_r)};
}

vector<pair<F,vector<F>>> compute_final_claim(vector<F> r, vector<vector<int>> FINAL){
    vector<F> B,_r = r; _r.pop_back();
    precompute_beta(_r,B);
    vector<F> y1(FINAL.size(),F(0));
    for(int j = 0; j < FINAL.size(); j++){
        for(int i = 0; i < FINAL[j].size(); i++){
            y1[j] += B[i]*F(FINAL[j][i]);
        }
    }
    
    return {make_pair(y1[0],_r),make_pair(y1[1],_r),make_pair(y1[2],_r)};
}


void compute_transcript_local(vector<vector<F>> &Tr,vector<sparse_eval_data> &data,vector<F> challenges, vector<vector<F>> &beta1, vector<vector<F>> &beta2, vector<F> r1, vector<F> r2){

    vector<F> base_beta1,base_beta2;
    precompute_beta(r1,base_beta1);
    precompute_beta(r2,base_beta2);
    
    for(int j = 0; j < data.size(); j++){
        Tr[2*j].resize(next_pow2(data[j].IDX1.size()),F(1));
        Tr[2*j+1].resize(next_pow2(data[j].IDX1.size()),F(1));
        for(int i = 0; i < data[j].IDX1.size(); i++){
            Tr[2*j][i] = challenges[0]*beta1[j][i] +  challenges[1]*F(data[j].RD1[i]) + challenges[2]*F(data[j].IDX1[i]) + F(1);
            Tr[2*j+1][i] = challenges[0]*beta1[j][i] +  challenges[1]*F(data[j].WR1[i]) + challenges[2]*F(data[j].IDX1[i]) + F(1);
        }
    }
    for(int j = 0; j < data.size(); j++){
        Tr[2*j+6].resize(next_pow2(data[j].IDX2.size()),F(1));
        Tr[2*j+1+6].resize(next_pow2(data[j].IDX2.size()),F(1));
        for(int i = 0; i < data[j].IDX2.size(); i++){
            Tr[2*j+6][i] = challenges[0]*beta2[j][i] +  challenges[1]*F(data[j].RD2[i]) + challenges[2]*F(data[j].IDX2[i]) + F(1);
            Tr[2*j+1+6][i] = challenges[0]*beta2[j][i] +  challenges[1]*F(data[j].WR2[i]) + challenges[2]*F(data[j].IDX2[i]) + F(1);
        }
    }
    for(int j = 0; j < data.size(); j++){
        Tr[2*j+12].resize(next_pow2(data[j].FINAL_FR1.size()),F(1));
        Tr[2*j+1+12].resize(next_pow2(data[j].FINAL_FR1.size()),F(1));
    
        for(int i = 0; i < data[j].FINAL_FR1.size(); i++){
            Tr[2*j+0+12][i] =   challenges[0]*base_beta1[i]+F(1)  +  challenges[2]*F(i);
            Tr[2*j+1+12][i] = challenges[0]*base_beta1[i] +  challenges[1]*F(data[j].FINAL_FR1[i]) + challenges[2]*F(i) + F(1);
        }
    }
    for(int j = 0; j < data.size(); j++){
        Tr[2*j+18].resize(next_pow2(data[j].FINAL_FR2.size()),F(1));
        Tr[2*j+1+18].resize(next_pow2(data[j].FINAL_FR2.size()),F(1));
        for(int i = 0; i < data[j].FINAL_FR2.size(); i++){
            Tr[2*j+18][i] =   challenges[2]*F(i) + F(1) + challenges[0]*base_beta2[i]; 
            Tr[2*j+1+18][i] = challenges[0]*base_beta2[i] +  challenges[1]*F(data[j].FINAL_FR2[i]) + challenges[2]*F(i) + F(1);
        }
    }
}

pair<F,vector<F>> prove_product_opt_local(vector<vector<F>> &input, vector<F> &output){
    
    int total_size;
    int size;
    
    
    for(int i = 0; i < input.size(); i++) {
        if(i > 0 && input[i].size() > input[i-1].size()){
            printf("Input is not sorted, exiting \n");
            exit(-1);
        }
        input[i].resize(next_pow2(input[i].size()),F(1));
        total_size += input[i].size();
        size = input[i].size();
    }
    
    vector<vector<F>> new_input;
    vector<F> buff(size);
    for(int i = 0; i < input.size(); i++){
        int ctr = 0;
        for(int j = 0; j < input[i].size()/size; j++){
            for(int k = 0; k < size; k++) buff[k] = input[i][ctr++];
            new_input.push_back(buff);
        }
    }
    
    vector<F> temp_out;
    pair<F,vector<F>> claim = prove_multiplication_tree_new(new_input,temp_out,F(0),F(0),{});
    int ctr = 0;
    output.resize(input.size(),F(1));
    for(int i = 0; i < input.size(); i++){
        for(int j = 0; j < input[i].size()/size; j++)output[i] *= temp_out[ctr++];
    }
    
    
    
    
    return claim;

}



pair<F,vector<F>> prove_sparse_eval_opt_local(F y, F a, F b, F c, vector<vector<F>> &beta1, vector<vector<F>> &beta2, vector<sparse_eval_data> &data ,vector<F> r1, vector<F> r2, double &pt, double &ps, double &vt){
    vector<vector<F>> Tr(24);
    vector<F> output;
    vector<int> order;
    
    //pt_cp.start();
    vector<F> challenges(3);
    clock_t t1 = clock();
    for(int i = 0; i < 3; i++) challenges[i] = hash_to_field({0}); 
    
    compute_transcript_local(Tr, data, challenges, beta1, beta2, r1, r2);
    
    //vector<F> test_v = Tr[13];
    
    sort_transcript(Tr, order);
    vector<F> debug_evals;
    
    pair<F,vector<F>> claim = prove_product_opt_local(Tr, output);
    
        vector<F> organized_output(output.size());
        for(int i = 0; i < output.size(); i++){
            organized_output[i] = output[order[i]];
        }
        for(int i = 0; i < 6; i++){
            if(organized_output[2*i]*organized_output[2*i+1+12] != organized_output[2*i+1]*organized_output[2*i+12]){
                printf("Error phase 2 %d\n",i);
            }
        }
    
    
    vector<F> r = claim.second;
    vector<F> evals;
    
    for(int i = 0; i < data.size(); i++){
        evals.push_back(evaluate_vector(beta1[i],r));
        evals.push_back(evaluate_vector(convert_to_field(data[i].RD1),r));
        evals.push_back(evaluate_vector(convert_to_field(data[i].IDX1),r));
    }
    for(int i = 0; i < data.size(); i++){
        evals.push_back(evaluate_vector(beta2[i],r));
        evals.push_back(evaluate_vector(convert_to_field(data[i].RD2),r));
        evals.push_back(evaluate_vector(convert_to_field(data[i].IDX2),r));
    }
    for(int i = 0; i < data.size(); i++) evals.push_back(evaluate_vector(convert_to_field(data[i].FINAL_FR1),r));
    for(int i = 0; i < data.size(); i++) evals.push_back(evaluate_vector(convert_to_field(data[i].FINAL_FR2),r));
    
    //vector<F> evals = batch_distributed_eval_opt(polys, r, claim.second[2], N);
    
    vector<F> beta_evals;
    
    for(int i = 0; i < data.size(); i++){
        beta_evals.push_back(evals[3*i]);
        beta_evals.push_back(evals[3*i + 9]);
    }

  
    order.clear();
    vector<F> v1,v2,v3;
    vector<vector<F>> _beta2_sorted,_beta1_sorted = beta1;
    vector<F> aggr_challenges = {a,b,c};
    sort_transcript(_beta1_sorted,order);    
    for(int i = 0; i < beta2.size(); i++) _beta2_sorted.push_back(beta2[order[i]]);
    
    for(int i = 0; i < beta1.size(); i++){
        v1.insert(v1.end(),_beta1_sorted[i].begin(),_beta1_sorted[i].end());
        v2.insert(v2.end(),_beta2_sorted[i].begin(),_beta2_sorted[i].end());
        vector<F> c_buff(_beta1_sorted[i].size(),aggr_challenges[order[i]]);
        v3.insert(v3.end(),c_buff.begin(),c_buff.end());
    }
    v1.resize(next_pow2(v1.size()),F(0));
    v2.resize(next_pow2(v2.size()),F(0));
    v3.resize(next_pow2(v3.size()),F(0));
    
    

        
    printf("OK\n");
    vector<pair<F,vector<F>>>  beta_evals2 =  cubic_sumcheck(y,v1,v2,v3,F(9));
    
    
    //for(int i = 0; i < )
    F __r = F::_random();
    r2 = beta_evals2[0].second;
    r2.insert(r2.begin(),__r);
    return make_pair((F(1)-__r)*beta_evals2[0].first + __r*beta_evals2[1].first,r2);
    //return make_pair(evaluate_vector(beta_evals,temp_r),betas_r);

}


void prove_sparse_eval(F y, F a, F b, F c, vector<F> &beta1, vector<F> &beta2, vector<sparse_eval_data> &data, double &pt, double &ps, double &vt){
    vector<F> challenges(3);
    vector<pair<F,vector<F>>> witness_claims;
    vector<pair<F,vector<F>>> index_claims;
    vector<pair<F,vector<F>>> claims;
    clock_t t1 = clock();
    for(int i = 0; i < 3; i++) challenges[i] = F::_random(); 
    vector<vector<F>> Tr(8);
    for(int j = 0; j < data.size(); j++){
        Tr[2*j].resize(next_pow2(data[j].IDX1.size()),F(1));
        Tr[2*j+1].resize(next_pow2(data[j].IDX1.size()),F(1));
        for(int i = 0; i < data[j].IDX1.size(); i++){
            Tr[2*j][i] = challenges[0]*beta1[data[j].IDX1[i]] +  challenges[1]*F(data[j].RD1[i]) + challenges[2]*F(data[j].IDX1[i]) + F(1);
            Tr[2*j+1][i] = challenges[0]*beta1[data[j].IDX1[i]] +  challenges[1]*F(data[j].WR1[i]) + challenges[2]*F(data[j].IDX1[i]) + F(1);
        }
    }
    Tr[6].resize(next_pow2(data[0].IDX1.size()),F(0));
    Tr[7].resize(next_pow2(data[0].IDX1.size()),F(0));
    
    vector<F> out1,out2,out3,out4;
    pair<F,vector<F>> claim = prove_multiplication_tree_new(Tr,out1,F(0),F(0),vector<F>());
    claims = compute_eval_claims(claim.second,beta1,{data[0].RD1,data[1].RD1,data[2].RD1},{data[0].IDX1,data[1].IDX1,data[2].IDX1},challenges,claim.first);
    witness_claims.push_back(claims[0]);
    witness_claims.push_back(claims[3]);
    witness_claims.push_back(claims[6]);
    for(int i = 0; i < 3; i++){
        index_claims.push_back(claims[3*i+1]);
        index_claims.push_back(claims[3*i+2]);
    }

    for(int j = 0; j < data.size(); j++){
        Tr[2*j].clear();Tr[2*j+1].clear();
        Tr[2*j].resize(next_pow2(data[0].FINAL_FR1.size()),F(1));
        Tr[2*j+1].resize(next_pow2(data[0].FINAL_FR1.size()),F(1));
    
        for(int i = 0; i < data[j].FINAL_FR1.size(); i++){
            Tr[2*j+0][i] = challenges[0]*F(beta1[i]) +  challenges[2]*F(i) + F(1);
            Tr[2*j+1][i] = challenges[0]*F(beta1[i]) +  challenges[1]*F(data[j].FINAL_FR1[i]) + challenges[2]*F(i) + F(1);
        }
   
    }
    Tr[6].clear();Tr[7].clear();
    Tr[6].resize(next_pow2(data[0].FINAL_FR1.size()),F(0));
    Tr[7].resize(next_pow2(data[0].FINAL_FR1.size()),F(0));
    
    claim = prove_multiplication_tree_new(Tr,out2,F(0),F(0),vector<F>());
    claims = compute_final_claim(claim.second, {data[0].FINAL_FR1,data[1].FINAL_FR1,data[2].FINAL_FR1});
    index_claims.push_back(claims[0]);
    index_claims.push_back(claims[1]);
    index_claims.push_back(claims[2]);

    printf(">OK1\n");
    for(int i = 0; i < out1.size()/2; i++){
        if(out1[2*i]*out2[2*i+1] != out1[2*i+1]*out2[2*i+0]){
            printf("Error phase 2\n");
            exit(-1);
        }
    }

    for(int j = 0; j < data.size(); j++){
        Tr[2*j+0].clear();Tr[2*j+1].clear();
        Tr[2*j+0].resize(next_pow2(data[0].IDX2.size()),F(1));
        Tr[2*j+1].resize(next_pow2(data[0].IDX2.size()),F(1));
        for(int i = 0; i < data[j].IDX2.size(); i++){
            Tr[2*j+0][i] = challenges[0]*beta2[data[j].IDX2[i]] +  challenges[1]*F(data[j].RD2[i]) + challenges[2]*F(data[j].IDX2[i]) + F(1);
            Tr[2*j+1][i] = challenges[0]*beta2[data[j].IDX2[i]] +  challenges[1]*F(data[j].WR2[i]) + challenges[2]*F(data[j].IDX2[i]) + F(1);
        }
    }
    Tr[6].clear();Tr[7].clear();
    Tr[6].resize(next_pow2(data[0].IDX2.size()),F(0));
    Tr[7].resize(next_pow2(data[0].IDX2.size()),F(0));
    
    claim = prove_multiplication_tree_new(Tr,out3,F(0),F(0),vector<F>());
    claims = compute_eval_claims(claim.second,beta2,{data[0].RD2,data[1].RD2,data[2].RD2},{data[0].IDX2,data[1].IDX2,data[2].IDX2},challenges,claim.first);
    witness_claims.push_back(claims[0]);
    witness_claims.push_back(claims[3]);
    witness_claims.push_back(claims[6]);
    for(int i = 0; i < 3; i++){
        index_claims.push_back(claims[3*i+1]);
        index_claims.push_back(claims[3*i+2]);
    }



    for(int j = 0; j < data.size(); j++){
        Tr[2*j+0].clear();Tr[2*j+1].clear();
        Tr[2*j+0].resize(next_pow2(data[0].FINAL_FR2.size()),F(1));
        Tr[2*j+1].resize(next_pow2(data[0].FINAL_FR2.size()),F(1));
        for(int i = 0; i < data[j].FINAL_FR2.size(); i++){
            Tr[2*j+0][i] = challenges[0]*F(beta2[i]) +  challenges[2]*F(i) + F(1);
            Tr[2*j+1][i] = challenges[0]*F(beta2[i]) +  challenges[1]*F(data[j].FINAL_FR2[i]) + challenges[2]*F(i) + F(1);
        }
    }
    Tr[6].clear();Tr[7].clear();
    Tr[6].resize(next_pow2(data[0].FINAL_FR2.size()),F(0));
    Tr[7].resize(next_pow2(data[0].FINAL_FR2.size()),F(0));
    
    claim = prove_multiplication_tree_new(Tr,out4,F(0),F(0),vector<F>());
    claims = compute_final_claim(claim.second, {data[0].FINAL_FR2,data[1].FINAL_FR2,data[2].FINAL_FR2});
    index_claims.push_back(claims[0]);
    index_claims.push_back(claims[1]);
    index_claims.push_back(claims[2]);

    for(int i = 0; i < out3.size()/2; i++){
        if(out3[2*i]*out4[2*i+1] != out3[2*i+1]*out4[2*i+0]){
            printf("Error phase 2\n");
            exit(-1);
        }
    }
    
    Tr.clear();
    vector<F> Y(3,0);
    for(int i = 0; i < 3; i++){
        vector<F> B1(next_pow2(data[0].IDX2.size()),F(0)),B2(next_pow2(data[0].IDX2.size()),F(0));
        
        for(int j = 0; j < data[i].IDX1.size(); j++){
            B1[j] = beta1[data[i].IDX1[j]];
            B2[j] = beta2[data[i].IDX2[j]];
            Y[i] += B1[j]*B2[j]; 
        }    
        vector<pair<F,vector<F>>> partial_claim = quadratic_sumcheck(Y[i],B1,B2,F(0));
        witness_claims.insert(witness_claims.end(),partial_claim.begin(),partial_claim.end());
    }
    if(y != a*Y[0]+b*Y[1]+c*Y[2]){
        printf("Error in sparse eval\n");
        exit(-12);
    }

    // Accumulate witness claims
    vector<F> witness(8*next_pow2(data[0].IDX2.size()),F(0));
    vector<F> acc(8*next_pow2(data[0].IDX2.size()),F(0));    
    vector<F> r; 
    for(int i = 0; i < 5; i++) r.push_back(F::_random());
    int l = next_pow2(data[0].IDX2.size());

    for(int i = 0; i < 3; i++){
        for(int j = 0; j < data[i].IDX1.size(); j++){
            witness[j + 2*i*l] = beta1[data[i].IDX1[j]];
        }
        for(int j = 0; j < data[i].IDX2.size(); j++){
            witness[j + (2*i+1)*l] = beta2[data[i].IDX2[j]];
        }
    }
    vector<F> beta; precompute_beta(witness_claims[0].second,beta);
    vector<F> _beta; precompute_beta(witness_claims[3].second,_beta);
    //for(int i = 0; i < 3; i++){
    for(int j = 0; j < l; j++){
        acc[j] = r[0]*beta[j];
        acc[j+2*l] = r[0]*beta[j];
        acc[j+4*l] = r[0]*beta[j];
        acc[j+l] = r[1]*_beta[j];
        acc[j+3*l] = r[1]*_beta[j];
        acc[j+5*l] = r[1]*_beta[j]; 
    }
    //}
    for(int i = 0; i < 3; i++){
        beta.clear();_beta.clear();
        precompute_beta(witness_claims[6+2*i].second,beta);
        for(int j = 0; j < l; j++){
            acc[j+(2*i)*l] += r[i+2]*beta[j];
            acc[j+(2*i+1)*l] += r[i+2]*beta[j];   
        }
    }
  
    F y_acc = r[0]*(witness_claims[0].first+witness_claims[1].first+witness_claims[2].first) + 
              r[1]*(witness_claims[3].first+witness_claims[4].first+witness_claims[5].first) + 
              r[2]*(witness_claims[6].first+witness_claims[7].first) + 
              r[3]*(witness_claims[8].first+witness_claims[9].first) +
              r[4]*(witness_claims[10].first+witness_claims[11].first);
    
    
    // TAKE THE EVALUATION CLAIM FROM THERE
    quadratic_sumcheck(y_acc,witness,acc,F(0));

    // Accumulate all other data
    vector<F> index_data(next_pow2(4*3*next_pow2(data[0].IDX2.size()) + 3*next_pow2(data[0].FINAL_FR1.size())+3*next_pow2(data[0].FINAL_FR2.size())),F(0));
    acc.clear();
    acc.resize(index_data.size(),F(0));
    beta.clear();
    precompute_beta(index_claims[index_claims.size()-1].second,beta);
    l = next_pow2(data[0].FINAL_FR2.size());
    for(int i = 0; i < data[0].FINAL_FR2.size(); i++){
        index_data[i] = data[0].FINAL_FR2[i];
        index_data[i + l] = data[1].FINAL_FR2[i];
        index_data[i + 2*l] = data[2].FINAL_FR2[i];
        acc[i] = beta[i];
        acc[i+l] = beta[i];
        acc[i+2*l] = beta[i];
    }

    int l1 = next_pow2(data[0].FINAL_FR1.size());
    beta.clear();
    precompute_beta(index_claims[index_claims.size()-10].second,beta);
    
    for(int i = 0; i < data[0].FINAL_FR1.size(); i++){
        index_data[i + 3*l] = data[0].FINAL_FR1[i];
        index_data[i+ 3*l + l1] = data[1].FINAL_FR1[i];
        index_data[i+ 3*l + 2*l1] = data[2].FINAL_FR1[i];
        acc[i+ 3*l] = beta[i];
        acc[i+ 3*l + l1] = beta[i];
        acc[i+ 3*l + 2*l1] = beta[i];
    }
    beta.clear();
    precompute_beta(index_claims[index_claims.size()-5].second,beta);
    precompute_beta(index_claims[0].second,_beta);
    
    int l2 = next_pow2(data[0].IDX1.size());
    for(int i = 0; i < data[0].IDX1.size(); i++){
        index_data[i + 3*l + 3*l1] = data[0].IDX1[i];
        index_data[i+  3*l + 3*l1 + l2] = data[1].IDX1[i];
        index_data[i+  3*l + 3*l1 + 2*l2] = data[2].IDX1[i];
        acc[i+ 3*l + 3*l1] = _beta[i];
        acc[i+ 3*l + 3*l1 + l2] = _beta[i];
        acc[i+ 3*l + 3*l1 + 2*l2] = _beta[i];
        
        index_data[i + 3*l + 3*l1+ 3*l2] = data[0].IDX2[i];
        index_data[i+  3*l + 3*l1+ 4*l2] = data[1].IDX2[i];
        index_data[i+  3*l + 3*l1+ 5*l2] = data[2].IDX2[i];
        acc[i+ 3*l + 3*l1 + 3*l2] = beta[i];
        acc[i+ 3*l + 3*l1 + 4*l2] = beta[i];
        acc[i+ 3*l + 3*l1 + 5*l2] = beta[i];
        
        index_data[i +  3*l + 3*l1+ 6*l2] = data[0].RD1[i];
        index_data[i+  3*l + 3*l1+ 7*l2] = data[1].RD1[i];
        index_data[i+  3*l + 3*l1+ 8*l2] = data[2].RD1[i];
        acc[i+ 3*l + 3*l1 + 6*l2] = _beta[i];
        acc[i+ 3*l + 3*l1 + 7*l2] = _beta[i];
        acc[i+ 3*l + 3*l1 + 8*l2] = _beta[i];
        
        index_data[i +  3*l + 3*l1+ 9*l2] = data[0].RD2[i];
        index_data[i+  3*l + 3*l1+ 10*l2] = data[1].RD2[i];
        index_data[i+ 3*l + 3*l1+ 11*l2] = data[2].RD2[i];
        acc[i+ 3*l + 3*l1 + 9*l2] = beta[i];
        acc[i+ 3*l + 3*l1 + 10*l2] = beta[i];
        acc[i+ 3*l + 3*l1 + 11*l2] = beta[i];
    }

    y_acc = F(0);
    for(int i = 0; i < index_claims.size(); i++){
        y_acc += index_claims[i].first;
    }
    quadratic_sumcheck(y_acc,index_data,acc,F(0));
    clock_t t2 = clock();
    pt += (double)(t2-t1)/(double)CLOCKS_PER_SEC;

    
}
