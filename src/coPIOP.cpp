#pragma once
#include "coPIOP.h"
#include "coSumcheck.h"
#include "sparse_eval.hpp"
#include "coPCS_utils.h"
#include "MPI_utils.hpp"
#include "Fiat_Shamir.h"
#include "coSumcheck_MPI.h"
#include "coPCS.h"
#include "Distributed_Sumcheck.h"
#include "timer.hpp"
// R1CS matrixes
vector<vector<pair<int, int>>> A,B,C;
// Transposed R1CS matrixes
vector<vector<pair<int,int>>> tA,tB,tC;
int logm,logn;
bool bit_method = false;
int index_rate = 4;
bool data_parallel = false;
extern double ps_plain; 
double cm = 0.0;
int gate_ctr = 0;
timer pt,pt_cp,temp_pc;
timer_cpu pt_cpu;
timer vt;


void transpose_R1CS_matrixes(){
    tA.resize(1<<logn);tB.resize(1<<logn);tC.resize(1<<logn);


    for(int i = 0; i < A.size(); i++){
        for(int j = 0; j < A[i].size(); j++){
            if(tA.size() <= A[i][j].first){
                printf("Error %d,%d\n",tA.size(),A[i][j].first);
                exit(-1);
            }
            tA[A[i][j].first].push_back(make_pair(A[i][j].first,A[i][j].second));
        } 
    }
    for(int i = 0; i < B.size(); i++){
        for(int j = 0; j < B[i].size(); j++) tB[B[i][j].first].push_back(make_pair(B[i][j].first,B[i][j].second));
    }

    for(int i = 0; i < C.size(); i++){
        for(int j = 0; j < C[i].size(); j++) tC[C[i][j].first].push_back(make_pair(C[i][j].first,C[i][j].second));
    }

    /*
    for(int i = 0; i < tA.size(); i++){
        if(tA[i].size() > 1 || tB[i].size() > 1 || tC[i].size() > 1){
            printf("> Error\n");
            exit(-1);
        }
    }
    */
    
}

gate add_input(){
    gate gt;
    gt.id = gate_ctr++;
    gt.id_left.push_back(-1);
    gt.id_right = -1;
    gt.type = 0;
    return gt;
}


gate add_mul(int size, int add_ctr){
    gate gt;
    vector<int> wires;
    wires.push_back((unsigned int)rand()%size);
    for(int i = 0; i < add_ctr-1; i++){
        while(true){
            bool is_dublicate = false;
            unsigned int num = (unsigned int)rand()%size;
            for(int j = 0; j < wires.size(); j++){
                if(num == wires[j]){
                    is_dublicate = true;
                    break;
                }
            }
            if(!is_dublicate){
                wires.push_back(num);
                break;
            }
        }
    }
    
    gt.id = gate_ctr++;
    gt.id_left = wires;
    gt.id_right = (unsigned int)rand()%size;
    gt.type = 2;
    return gt;
}

// Dummy computation represeting multiplication tree
// 0: Default, multree
// 1: Random circuit
void generate_R1CS_matrixes(size_t size, int type){
    int n = size;
    int m = 0;
    int counter = 0;
    if(type == 0){
        A.resize(size); B.resize(size); C.resize(size);
        for(int j = 0; j < (int)log2(size); j++){
            for(int i = 0; i < size/(1<<(j+1)); i++){
                A[counter].resize(1);B[counter].resize(1);C[counter].resize(1);
                A[counter][0] = {2*i + m,i+m/2};
                B[counter][0] = {2*i+1+m,i+m/2};
                C[counter][0] = {n+i,i+m/2};
                counter++;
            }
            m+=size/(1<<(j));
            n+=size/(1<<(j+1));
        }
        logm = (int)log2(size);
        logn = (int)log2(size)+1;    
    }else{
        vector<gate> gates;
        for(int i = 0; i < size/16; i++) gates.push_back(add_input());
        int add_ctr = 0;
        int additions = 0;
        srand(42);
        for(int i = size/16; i < size; i++){
            if(rand()%2 == 0){
                add_ctr++;
                additions++;
            }else{
                gates.push_back(add_mul(gates.size(),add_ctr));
                add_ctr = 0;
            }
        }
        if(add_ctr != 0) gates.push_back(add_mul(gates.size(), add_ctr));
        
        A.resize(gates.size());B.resize(gates.size());C.resize(gates.size());
        for(int i = size/16; i  < A.size(); i++){
            A[i].resize(gates[i].id_left.size());B[i].resize(1);C[i].resize(1);
            for(int j = 0; j < A[i].size(); j++){
                A[i][j] = {gates[i].id_left[j],gates[i].id-size/16};
            }
            B[i][0] = {gates[i].id_right,gates[i].id-size/16};
            C[i][0] = {gates[i].id,gates[i].id-size/16};
        }
        logm = (int)log2(next_pow2(gates.size()-size/16));
        logn = (int)log2(next_pow2(gates.size()));    
    
    }
    transpose_R1CS_matrixes();
}




void reduce_R1CS_matrixes(size_t size, vector<F> r, vector<F> &RA, vector<F> &RB, vector<F> &RC){
    vector<F> beta;
    precompute_beta(r,beta);
    RA.resize(1<<logn,F(0));RB.resize(1<<logn,F(0));RC.resize(1<<logn,F(0));
    for(int i = 0; i < A.size(); i++){
        for(int j = 0; j < A[i].size(); j++){
            RA[A[i][j].first] += beta[A[i][j].second];
        }
        for(int j = 0; j < B[i].size(); j++){
            RB[B[i][j].first] += beta[B[i][j].second];
        }
        for(int j = 0; j < C[i].size(); j++){
            RC[C[i][j].first] += beta[C[i][j].second];
        }
    }
}

void secret_share_proving_data(vector<F> &witness, 
                               vector<vector<F>> &tr, 
                               vector<vector<F>> &W, 
                               vector<vector<vector<F>>> &Tr, int k, int _k, int N){
    W.resize(witness.size()/k);
    Tr.resize(3);
    int ctr = 0;
    for(int i = 0; i < W.size(); i++){
        W[i].resize(_k);
        for(int j = 0; j < k; j++){
            W[i][j] = witness[ctr++];
        }
        for(int j = k; j < _k; j++){
            W[i][j] = random();
        }
        fft(W[i],(int)log2(_k),true);
        W[i].resize(N,0);
        fft(W[i],(int)log2(N),false);
    } 
    for(int i = 0; i < Tr.size(); i++){
        Tr[i].resize(tr[i].size()/k);
        ctr = 0;
        for(int j = 0; j < Tr[i].size(); j++){
            Tr[i][j].resize(_k);
            for(int l = 0; l < k; l++){
                Tr[i][j][l] = tr[i][ctr++];
            }
            for(int l = 0; l < _k; l++){
                Tr[i][j][l] = random();
            }
            fft(Tr[i][j],(int)log2(_k),true);
            Tr[i][j].resize(N,0);
            fft(Tr[i][j],(int)log2(N),false);
        }
    }
}



vector<pair<F,vector<F>>> prove_phase1( vector<F> vL, 
                                        vector<F> vR, 
                                        vector<F> vO, 
                                        vector<F> rL,
                                        vector<F> rR,
                                        vector<F> rO,
                                        vector<F> R1,
                                        vector<F> R2, 
                                        int N, int _k, int k,  double &ps){

    
    pt_cp.start();
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    

    vector<F> _r1,_r2;
    
    for(int i = 0; i < (int)log2(vL.size()); i++)_r1.push_back(hash_to_field({0}));
    for(int i = 0; i < (int)log2(k); i++)_r2.push_back(hash_to_field({0}));
    
    
    vector<F> beta1,beta2;
    //precompute_beta(_r1,beta1);
    precompute_beta(_r2,beta2);
    
    F y = 0;
    for(int i = 0; i < rL.size(); i++){
        y += _beta(i,_r1)*(rL[i]*rR[i] - rO[i]);
    }
    vector<u64> buff_u64(2);
    pt_cp.end();
    
    if(rank == 0){
        vector<F> Y(N);
        Y[0] = y;
        for(int i = 1; i < N; i++){
            MPI_Recv(buff_u64.data(),2,MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            Y[i].real = buff_u64[0];
            Y[i].img = buff_u64[1];
        }
        pt_cp.start();
        fft(Y,(int)log2(N),true);
        F mul = F(1);
        F omega = getRootOfUnity(1+(int)log2(N)).inv();
        for(int i = 0; i < Y.size(); i++){
            Y[i] = mul*Y[i];
            mul = omega*mul;
        }
        fft(Y,(int)log2(N),false);
        y = 0;
        for(int i = 0; i < k; i++){
            y += beta2[i]*Y[i*N/_k];
        }
        buff_u64 = {y.real,y.img};
        pt_cp.end();
    
    }else{
        buff_u64 = {y.real,y.img};
        cm += 8*buff_u64.size()/1024.0;
        MPI_Send(buff_u64.data(),2,MPI_UINT64_T,0,0,MPI_COMM_WORLD);
    }
    if(rank == 0) cm += (N-1)*8*buff_u64.size()/1024.0;
    MPI_Bcast(buff_u64.data(),2,MPI_UINT64_T,0,MPI_COMM_WORLD);
    
    pt_cp.start();
    
    y.real = buff_u64[0];y.img = buff_u64[1];
    vector<F> r1 = _r1,r2 = _r2;
    r1.push_back(hash_to_field({0}));
    vL.resize(2*vL.size(),F(0));
    vR.resize(2*vL.size(),F(0));
    vO.resize(2*vL.size(),F(0));
    for(int i = vL.size()/2; i < vL.size()/2+rL.size(); i++){
        vL[i] = rL[i-vL.size()/2];
        vR[i] = rR[i-vL.size()/2];
        vO[i] = rO[i-vL.size()/2];
    }
    
    y = r1[r1.size()-1]*y;
    
    vector<F> r = r1;r.insert(r.begin(),r2.begin(),r2.end());
    pt_cp.end();
    
    return _zero_check_sumcheck(y,vL,vR,vO,R1,R2,r,N,_k,k,ps);    
}

void compute_beta_shares(vector<F> &shares, vector<F> r, int k, int N, int _k){
    shares.clear();
    vector<F> r1,r2,b1;
    for(int i = 0; i < (int)log2(k); i++) r1.push_back(r[i]);
    for(int i = (int)log2(k); i < r.size(); i++) r2.push_back(r[i]);
    
    precompute_beta(r1,b1);precompute_beta(r2,shares);
    vector<F> buff(_k,0);
    
    for(int i = 0; i < k; i++) buff[i] = b1[i];
    fft(buff,(int)log2(buff.size()),true);
    buff.resize(2*N,F(0));
    fft(buff,(int)log2(buff.size()),false);
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    for(int i = 0; i < shares.size(); i++){
        shares[i] = buff[2*rank+1]*shares[i];
    }

}

vector<pair<F,vector<F>>> prove_phase2(
                  vector<F> &w, 
                  vector<F> &r_w, 
                  vector<F> rL,
                  vector<F> rR,
                  vector<F> rO,
                  vector<F> &RA, 
                  vector<F> &RB, 
                  vector<F> &RC,
                  vector<F> &R1,
                  vector<F> &R2, 
                  vector<F> r,
                  F yL,F yR, F yO,
                  int N, int size,
                  int _k, int k, F &a, F &b, F &c,  double &ps){

    
    RA.clear();RB.clear();RC.clear();
    
    vector<F> _r = r;_r.pop_back();

    pt_cp.start();
    _reduce_R1CS_matrixes(size, _r, RA, RB, RC, N);
    
        
    a = hash_to_field({0});
    b = hash_to_field({0}); c = hash_to_field({0});  
    
    // Initialize main inputs
    w.insert(w.end(),r_w.begin(),r_w.end());
    w.resize(next_pow2(w.size()),F(0));
    rL.resize(w.size(),F(0));
    for(int i = 0; i < rR.size(); i++) rL[i] = a*rL[i] + b*rR[i] + c*rO[i];    
    
    // Initialize secondary inputs
    vector<F> R_aggr(RA.size(),F(0));
    
    for(int i = 0; i < RA.size(); i++){
        R_aggr[i] = (F(1)- r[r.size()-1])*(a*RA[i] + b*RB[i] + c*RC[i]);
    }
   
   
    F i = (F(1)- r[r.size()-1]).inv();
    
    pt_cp.end();
    secret_share_vector(R_aggr, _k, k, N);
    pt_cp.start();
    R_aggr.resize(2*R_aggr.size(),F(0));

    vector<F> beta_shares;
    
    compute_beta_shares(beta_shares, _r, k, N, _k);
    for(int i = 0; i < beta_shares.size(); i++){
        beta_shares[i] = r[r.size()-1]*beta_shares[i];
    }
    beta_shares.resize(4*beta_shares.size(),F(0));
    pt_cp.end();

    vector<pair<F,vector<F>>> claim = _quadratic_batch_sumcheck(a*yL + b*yR + c*yO, w, R_aggr, rL, beta_shares, R1,R2,N, _k, k, ps);
    claim[1].first = (F(1)-claim[1].second[claim[1].second.size()-1]).inv()*i*claim[1].first;
    return claim;
}


void get_bits(vector<short> &buff, int idx1, int idx2){
    for(int i = 0; i < logm; i++){
        buff[i] = 0;
        if(idx1&1){
            buff[i] = 1;
        }
        idx1 = idx1>>1;
    }
    for(int i = logm; i < logm+logn; i++){
        buff[i] = 0;
        if(idx2&1){
            buff[i] = 1;
        }
        idx2 = idx2>>1;
    }

}

void prepare_matrix_data(vector<vector<pair<int, int>>> &M, vector<vector<int>> &idx, vector<vector<short>> &bits){
    int mask1 = 0;
    int mask2 = 0;
    for(int i = 0; i < logm/2; i++){
        mask1 = mask1<<1;
        mask1 += 1;
    }
    for(int i = 0; i < logn/2; i++){
        mask2 = mask2<<1;
        mask2 += 1;
    }
    int idx_size = 0;
    for(int i = 0; i < M.size(); i++){
        idx_size+= M[i].size();
    }
    
    idx.resize(idx_size);
    bits.resize(idx_size);
    int ctr = 0;
    vector<short> buff(logm+logn,0);
    for(int i = 0; i < M.size(); i++){
        for(int j = 0; j < M[i].size(); j++){
            idx[ctr].resize(4);
            idx[ctr][0] = i&mask1;
            idx[ctr][1] = i>>(logm/2);
            if(idx[ctr][0] + (idx[ctr][1]<<(logm/2)) != i){
                printf("Error in matrix preperation 1,%d,%d,%d\n",i,mask1,idx[ctr][1]);
                exit(-1);
            }
            idx[ctr][2] = M[i][j].first&mask2; 
            idx[ctr][3] = M[i][j].first>>(logn/2); 
            if(idx[ctr][2] + (idx[ctr][3]<<(logn/2)) != M[i][j].first){
                printf("Error in matrix preperation 2,%d\n",M[i][j].first);
                exit(-1);
            }
            get_bits(buff,i,M[i][j].first);
            bits[ctr] = buff;
            ctr++;

        }
    }
}


void compute_witness_vector(vector<F> r1, vector<F> r2, vector<sparse_eval_data> &data, vector<F> &witness, int N, double &pt){
    vector<F> r11,r12,r21,r22;
    for(int i = 0 ; i < r1.size()/2; i++){
        r11.push_back(r1[i]);
    }
    for(int i = r1.size()/2; i < r1.size(); i++){
        r12.push_back(r1[i]);
    }
    for(int i = 0; i < r2.size()/2; i++){
        r21.push_back(r2[i]);
    }
    for(int i = r2.size()/2; i < r2.size(); i++){
        r22.push_back(r2[i]);
    }
    int mask1 = 0;
    int mask2 = 0;
    for(int i = 0; i < logm/2; i++){
        mask1 = mask1<<1;
        mask1 += 1;
    }
    for(int i = 0; i < logn/2; i++){
        mask2 = mask2<<1;
        mask2 += 1;
    }

    vector<F> beta11,beta12,beta21,beta22;
    
    clock_t t1 = clock();
    precompute_beta(r11,beta11);
    precompute_beta(r12,beta12);
    precompute_beta(r21,beta21);
    precompute_beta(r22,beta22);
    clock_t t2 = clock();
    pt += (double)(t2-t1)*N/(double)CLOCKS_PER_SEC;
    witness.resize(8*next_pow2(data[0].IDX1.size()),F(0));
    int ctr = 0;
    t1 = clock();
    for(int i = 0; i < data.size(); i++){
        for(int j = 0; j < data[i].IDX1.size(); j++){
            int idx1 = data[i].IDX1[j];
            int idx11 = idx1&mask1;
            int idx12 = idx1>>(logm/2);
            witness[ctr] = beta11[idx11]*beta12[idx12];
            ctr++;
        }
        ctr+= next_pow2(data[i].IDX1.size())-data[i].IDX1.size();
        for(int j = 0; j < data[i].IDX2.size(); j++){
            int idx2 = data[i].IDX2[j];
            int idx21 = idx2&mask2;
            int idx22 = idx2>>(logn/2);
            witness[ctr] = beta21[idx21]*beta22[idx22];
            ctr++;

        }
        ctr+= next_pow2(data[i].IDX1.size())-data[i].IDX1.size();

    }
    t2 = clock();
    pt += (double)(t2-t1)/(double)CLOCKS_PER_SEC;

}

void evaluate_sparse_matrix(size_t size, int N, vector<F> r1, vector<F> r2, F y, F a, F b, F c, double &pt, double &ps, double &vt){
    vector<F> witness;
    vector<vector<F>> R;
    vector<vector<F>> Code;
    vector<vector<vector<_hash>>> MT;     
    vector<sparse_eval_data> data;
    
    prepare_R1CS_data(A, B, C, logm, logn, data);
    vector<F> beta1,beta2;precompute_beta(r1,beta1);precompute_beta(r2,beta2);
    
    compute_witness_vector(r1,r2,data,witness,N,pt);
    
    //COMMIT
    //plain_commit(witness,N/2,N,N,R,Code,MT,pt,vt,ps,cm);
    prove_sparse_eval(y,a,b,c, beta1, beta2, data,pt, ps, vt);
    
    vector<F> r,_r1,_r2;
    for(int i = 0; i < (int)log2(witness.size()); i++){
        r.push_back(F::_random());
        if(i < (int)log2(N/2)){
            _r1.push_back(r[i]);
        }else{
            _r2.push_back(r[i]);
        }
    }
    clock_t t1 = clock();
    precompute_beta(_r1,beta1);
    precompute_beta(_r2,beta2);
    clock_t t2 = clock();
    pt += N*(double)(t2-t1)/(double)CLOCKS_PER_SEC;
    y = evaluate_vector(witness,r);
    // OPEN
    //plain_open(y,Code,R,MT,beta1,beta2,N/2,pt,vt,ps,500,false);

    
    //r1.insert(r1.end(),r2.begin(),r2.end());
    //prepare_matrix_data(A,idx,bits);
    //prove_sparse_eval_bit(r1, evaluate_vector(RA,r2), bits, idx, logm, logn, N, pt, vt, ps);
    //printf("%lf\n",pt/N);
    
}

void commit_sparse_eval_witness(vector<vector<F>> &beta1, vector<vector<F>> &beta2,vector<F> &codeword ,vector<F> &row_data, MT &Com, int k, int N){
    vector<F> data;
    vector<vector<F>> buff;
    buff = beta1;
    
    vector<int> order;

    sort_transcript(buff, order);
    
    data = convert2vector(buff);
    buff.clear();
    data.resize(next_pow2(data.size()),F(0));
    
    //for(int i = 0; i < beta1.size(); i++) data.insert(data.end(),beta1[i].begin(),beta1[i].end());
    for(int i = 0; i < beta2.size(); i++) data.insert(data.end(),beta2[order[i]].begin(),beta2[order[i]].end());
    data.resize(next_pow2(data.size()),F(0));
    plaintext_commit(data, codeword,row_data,Com,k,N);
}

void open_sparse_eval(vector<F> &codeword, vector<F> &row_data, vector<F> r, MT &Com, F y,int l, int k, int N, double &ps){
    vector<F> r1,r2,v1,v2;

    for(int i = 0; i < (int)log2(k); i++) r2.push_back(r[i]);
    for(int i = r2.size(); i < r.size() ; i++) r1.push_back(r[i]);
    
    precompute_beta(r1,v1);precompute_beta(r2,v2);
    
    open_plaintext(codeword, row_data, v1, v2, Com, y, l, k, N, ps,false);
}

void sparse_matrix_evaluation(F y, F a, F b, F c, vector<F> r1,vector<F> r2, vector<sparse_eval_data> &index, int N, double &ps){

    vector<vector<F>> beta1(3),beta2(3);
    r1.pop_back();r2.pop_back();
    if(r1.size() != logm){
        printf("Wrong dimensions 1\n");
        exit(-1);
    }
    if(r2.size() != logn){
        printf("Wrong dimensions 2\n");
        exit(-1);
    }
    pt_cp.start();

    compute_R1CS_betas(r1,  r2, index, beta1, beta2, logm, logn, N);
    vector<F> codeword,row_data;
    MT Com;
    pt_cp.end();

    commit_sparse_eval_witness(beta1, beta2, codeword , row_data, Com, N/2,  N);
    //pair<F,vector<F>> claim = _prove_sparse_eval(y, a, b, c, beta1, beta2, index,r1,r2, N);
    pair<F,vector<F>> claim = _prove_sparse_eval_opt(y, a, b, c, beta1, beta2, index,r1,r2, N);

    open_sparse_eval(codeword,row_data,claim.second,Com,claim.first,500,N/2,N,ps);
}

void aggregate_random_evaluations(vector<pair<F,vector<F>>> claims1, vector<pair<F,vector<F>>> claims2,
                                 vector<F> R, vector<F> _R,vector<F> codeword, vector<F> _codeword, MT &CR, F a, F b, F c, int N, int k, int _k, double &ps){
    
    
    
    pt_cp.start();
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    // Evaluate claims of _R, then apply the sumcheck to aggregate partial claims into one
    int logk = (int)log2(k);
    vector<vector<F>> vectors(10);
    vectors[0].resize(4);vectors[1].resize(4);vectors[2].resize(4);
    vectors[3].resize(logn-logk+2);vectors[4].resize(logn-logk+2);
    vectors[5].resize(logm-logk+2);vectors[6].resize(logm-logk+2);
    vectors[7].resize(4);vectors[8].resize(4);vectors[9].resize(4);
    for(int i = 0; i < 4; i++){
        vectors[0][i] = _R[i];
        vectors[1][i] = _R[i+4];
        vectors[2][i] = _R[i+8];
        vectors[7][i] = R[i];
        vectors[8][i] = R[i+4];
        vectors[9][i] = R[i+8];
    }
    for(int i = 0; i < logn+2-logk; i++){
        vectors[3][i] = _R[i+12];
        vectors[4][i] = _R[i+12+logn-logk+2];
    }
    for(int i = 0; i < logm+2-logk; i++){
        vectors[5][i] = _R[i+12+2*(logn -logk + 2)];
        vectors[6][i] = _R[i+12+2*(logn -logk + 2) + logm-logk+2];
    }
    vector<vector<vector<F>>> betas(10);
    for(int i = 0; i < 7; i++) betas[i].resize(2);
    vector<F> r1,r2;
    
    for(int i = 0; i < (int)log2(k); i++) r2.push_back(claims1[0].second[i]);
    for(int i = (int)log2(k); i < claims1[0].second.size(); i++) r1.push_back(claims1[0].second[i]);
    
    for(int i = 0; i < logm-logk; i++) betas[5][0].push_back(_beta(1<<i,r1));
    
    betas[5][0].push_back(_beta((1<<(logm-logk))-2,r1));
    betas[5][0].push_back(_beta((1<<(logm-logk))-1,r1));
    precompute_beta(r2,betas[5][1]);
    betas[6] = betas[5];

    r1.clear();r2.clear();
    for(int i = 0; i <  (int)log2(k); i++) r2.push_back(claims2[0].second[i]);
    for(int i = (int)log2(k); i < claims2[0].second.size(); i++) r1.push_back(claims2[0].second[i]);
    for(int i = 0; i < (logn-logk); i++) betas[3][0].push_back(_beta(1<<i,r1));
    
    betas[3][0].push_back(_beta((1<<(logn-logk))-2,r1));
    betas[3][0].push_back(_beta((1<<(logn-logk))-1,r1));
    precompute_beta(r2,betas[3][1]);
    betas[4] = betas[3];
    for(int i = 0; i < 4; i++){
        betas[0][0].push_back(_beta(i,r1));
    }
    betas[0][1] = betas[3][1];
    betas[1] = betas[0];betas[2] = betas[0];
    betas[7] = betas[0];betas[8] = betas[0];
    betas[9] = betas[0];
    
    vector<F> evals = batch_ip(vectors, betas, N, k,_k);    
    vector<F> _c(7);
    for(int i = 0; i < 7; i++) _c[i] = hash_to_field({});
    F _b = hash_to_field({});
    for(int i = 0; i < R.size(); i++){
        R[i] += _b*_R[i];
    }
    
    
    /*
    vector<u64> R_int(2*R.size());
    vector<vector<F>> Masked_R_shares,Masked_R;
    if(rank == 0){
        Masked_R_shares.resize(R.size());Masked_R.resize(R.size());
        for(int i = 0; i < Masked_R_shares.size(); i++){
            Masked_R_shares[i].resize(N);
            Masked_R[i].resize(k);
            Masked_R_shares[i][0] = R[i];
        }
        for(int i = 1; i < N; i++){
            MPI_Recv(R_int.data(),R_int.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            field_vector_deserialize(R_int,R);
            for(int j = 0; j < R.size(); j++) Masked_R_shares[j][i] = R[j];
        }
        for(int i = 0; i < Masked_R_shares.size(); i++){
            fft(Masked_R_shares[i],(int)log2( Masked_R_shares[i].size()),true);
            F omega = getRootOfUnity(1+(int)log2(N));
            omega = omega.inv();
            F mul = F(1);
            for(int j = 0; j < Masked_R_shares[i].size(); j++){
                Masked_R_shares[i][j] = mul*Masked_R_shares[i][j];
                mul = omega*mul;
            }
            fft(Masked_R_shares[i],(int)log2(Masked_R_shares[i].size()),false);
            for(int j = 0; j < k; j++) Masked_R[i][j] = Masked_R_shares[i][N*j/_k];
        }

    }else{
        field_vector_serialize(R,R_int);
        MPI_Send(R_int.data(), R_int.size(), MPI_UINT64_T, 0,0, MPI_COMM_WORLD);
    }
    if(rank == 0){
        if(claims2[2].first != a*evals[7]+b*evals[8] + c*evals[9]){
            printf("ERROR\n");
        }
        F sum = _c[0]*evals[7]+_c[1]*evals[8]+_c[2]*evals[9] + _c[3]*claims2[4].first +_c[4]*claims2[5].first  + _c[5]*claims1[4].first + _c[6]*claims1[5].first;
        for(int i = 0; i < 7; i++) sum += _b*_c[i]*evals[i];

        vector<F> v1,v2;
        v1 = convert2vector((Masked_R));
        
        
        int ctr = 0;
        v2.resize(v1.size(),F(0));        
        for(int i = 0; i < betas.size()-3; i++){
            for(int n = 0; n < betas[i][0].size(); n++){
                for(int j = 0; j < betas[i][1].size(); j++){
                    v2[ctr] = _c[i]*betas[i][0][n]*betas[i][1][j];
                    ctr++;
                }
            }
        }
        
        v1.resize(next_pow2(v1.size()),F(0));
        v2.resize(next_pow2(v2.size()),F(0));

    }
    */
   if(rank == 0){
        if(claims2[2].first != a*evals[7]+b*evals[8] + c*evals[9]){
            printf("ERROR\n");
        }
   }
   
    
    F sum = _c[0]*evals[7]+_c[1]*evals[8]+_c[2]*evals[9] + _c[3]*claims2[4].first +_c[4]*claims2[5].first  + _c[5]*claims1[4].first + _c[6]*claims1[5].first;
    for(int i = 0; i < 7; i++) sum += _b*_c[i]*evals[i];

    vector<F> v1 = R,v2;
    for(int i = 0; i < vectors.size()-3; i++){
        vector<F> buff = betas[i][1];
        buff.resize(_k,F(0));
        fft(buff,(int)log2(buff.size()),true);
        buff.resize(2*N,0);
        fft(buff,(int)log2(buff.size()),false);
        for(int j = 0; j < betas[i][0].size(); j++){
            betas[i][0][j] = _c[i]*buff[2*rank+1]*betas[i][0][j];
        }
        v2.insert(v2.end(),betas[i][0].begin(),betas[i][0].end());
    }
    v1.resize(next_pow2(v1.size()),F(0));
    v2.resize(next_pow2(v1.size()),F(0));
    pt_cp.end();
   
    vector<pair<F,vector<F>>> claims = _quadratic_cosumcheck(sum,v1,v2,N,_k,k,ps);
    pt_cp.start();
   
    r1.clear();r2.clear();
    for(int i = 0; i < logk; i++) r2.push_back(claims[0].second[i]);
    for(int i = logk; i < claims[0].second.size(); i++) r1.push_back(claims[0].second[i]);
    v1.clear();v2.clear();precompute_beta(r1,v1);precompute_beta(r2,v2);
    
    R.resize(next_pow2(R.size()),0);
    for(int i = 0; i < codeword.size(); i++){
        codeword[i] += _b*_codeword[i];
    }
    pt_cp.end();
    
    open_plaintext(codeword,R,v1,v2,CR,claims[0].first,500,k,N,ps,true);
}


void init_dummy_index_commitment(vector<sparse_eval_data> &data, vector<F> &row_data, vector<F> &codeword, MT &index_Com, int rate, int N){
    int size = 0;
    for(int i = 0; i < data.size(); i++){
        size += data[i].FINAL_FR1.size();
        size += data[i].FINAL_FR2.size();
        size += data[i].IDX1.size();
        size += data[i].IDX2.size();
        size += data[i].RD1.size();
        size += data[i].RD2.size();
    }
    size = next_pow2(size);
    row_data = generate_randomness(size);
    codeword = generate_randomness(rate*size);
    distributed_MT(codeword, index_Com, N);
    
}


void open_index(vector<F> &index_data,vector<F> &codeword, MT &index_Com, int N,double &ps){
    pt_cp.start();
    vector<F> r1,r2,beta1,beta2;
    for(int i = 0; i < (int)log2(index_data.size()); i++) r1.push_back(hash_to_field({}));
    for(int i = 0; i < (int)log2(N); i++) r2.push_back(hash_to_field({}));
    precompute_beta(r1,beta1);precompute_beta(r2,beta2);
    pt_cp.end();
    open_plaintext(codeword,index_data,beta1,beta2,index_Com,F(0),100,N,N,ps,false,false);

}

void coPIOP_prove(size_t size, int N, int _k, int k, int cir_type){
    double ps = 0.0;
    int logk = (int)log2(k);
    
    vector<F> witness,vL,vO,vR,R,_R;
    vector<F> r_witness;
    vector<vector<F>> mask_shares,mask_data,C_mask;
    vector<F> RA,RB,RC;
    vector<sparse_eval_data> index;
    MT CR,_CR,index_Com,Com;
    vector<MT> Com_mask;
    vector<F> codeword,row_data,codeword_R,_codeword_R,index_codeword,index_data;
    distribute_index(N, size, index,cir_type);
    distribute_proving_data(vL, vR, vO, witness, N, size, _k, k,cir_type);
    setup_randomness(R, N, _k, k,500 + 2*(logm + logn - 2*logk + 4) + 12+1);
    setup_randomness(_R, N, _k, k,500 + 2*(logm + logn - 2*logk + 4) + 12+1);
    dummy_setup(r_witness, mask_shares, N, 1<<logn, k, _k, 500);
    prepare_mask_shares(mask_shares, mask_data, C_mask, Com_mask, N, 1<<logn, k, _k, 500);
    //setup_randomness(r_witness, N, _k, k,500);
    commit_randomness(R, _R, codeword_R, _codeword_R, CR, _CR, N);
    // To ease development, we initialize a dummy index commitment. In practice, we could let the indexer 
    // generate such a commitment in a preprocessing phase.
    if(witness.size() < r_witness.size()){
        printf("Circuit too small. Select fewer parties\n");
        return;
    }
    init_dummy_index_commitment(index,index_data,index_codeword,index_Com,index_rate,N);
    

    MPI_Barrier(MPI_COMM_WORLD);
    pt_cp.reset();
    pt.start();
    pt_cpu.start();
    temp_pc.start();
    commit(codeword, row_data, witness, r_witness, Com, 500, k, _k, N);
    vector<F> rL(4),rR(4),rO(4),R1(logn-logk +2),R2(logn+2-logk ),R3(logm-logk +2),R4(logm+2-logk );
    for(int i = 0; i < 4; i++){
        rL[i] = R[i];
        rR[i] = R[i+4];
        rO[i] = R[i+8];
    }
    for(int i = 0; i < logn -logk +2; i++){
        R1[i] = R[i+12];
        R2[i] = R[i+12 + logn-logk +2];
    }
    for(int i = 0; i < logm-logk+2; i++){
        R3[i] = R[i+12+2*(logn -logk + 2)];
        R4[i] = R[i+12+2*(logn -logk + 2)+logm-logk+2];
    }
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    temp_pc.end();
    printf("Phase 1: %lf\n",temp_pc.get_time());temp_pc.reset();
    temp_pc.start();
    vector<pair<F,vector<F>>> claims1 = prove_phase1(vL, vR, vO, rL, rR, rO,R3,R4, N,_k, k, ps);
    temp_pc.end();
    printf("Phase 2: %lf\n",temp_pc.get_time());temp_pc.reset();
    F a,b,c;
    temp_pc.start();
    vector<pair<F,vector<F>>> claims2 = prove_phase2(witness, r_witness, rL, rR, rO, RA, RB, RC,R1,R2, claims1[0].second, claims1[0].first,claims1[1].first,claims1[2].first,N, size, _k, k, a,b,c, ps);
    temp_pc.end();
    printf("Phase 3: %lf\n",temp_pc.get_time());temp_pc.reset();
    
    
    temp_pc.start();
    aggregate_random_evaluations(claims1,  claims2, R,  _R,codeword_R,_codeword_R,CR ,a,b,c, N, k,  _k,ps);
    temp_pc.end();
    printf("Phase 4: %lf\n",temp_pc.get_time());temp_pc.reset();
    
    //return;
    if(!data_parallel){
        temp_pc.start();
        sparse_matrix_evaluation(claims2[1].first,a,b,c,
                             claims1[0].second,claims2[0].second,index,N,ps);
        temp_pc.end();
        printf("Phase 5: %lf\n",temp_pc.get_time());temp_pc.reset();
    
        temp_pc.start();
        open_index(index_data,index_codeword, index_Com, N,ps);
        temp_pc.end();
        printf("Phase 6: %lf\n",temp_pc.get_time());temp_pc.reset();
    
    }
    temp_pc.start();
    open_zk(codeword,C_mask,row_data,mask_data,Com,Com_mask, claims2[0].second,claims2[0].first,500,k,_k,(1<<logm),N,ps);
    temp_pc.end();
    printf("Phase 7: %lf\n",temp_pc.get_time());temp_pc.reset();
    pt.end();
    pt_cpu.end();
    MPI_Barrier(MPI_COMM_WORLD);
    if(rank == 0){
        vector<double> buff(3);
        printf("Id : %d, Pt: %lf, CPU Only Pt: %lf, Computation only: %lf, Vt: %lf\n", rank, pt.get_time(),pt_cpu.get_time(),pt_cp.get_time(),vt.get_time());
        for(int i = 1; i < N; i++){
            MPI_Recv(buff.data(), 3,MPI_DOUBLE,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            printf("Id : %d, Pt: %lf, CPU Only Pt: %lf, Computation only: %lf\n", i, pt.get_time(),pt_cpu.get_time(),pt_cp.get_time());
        }    
    }else{
        vector<double> buff = {pt.get_time(),pt_cpu.get_time(),pt_cp.get_time()};
        MPI_Send(buff.data(), 3,MPI_DOUBLE,0,0,MPI_COMM_WORLD);   
    }
    MPI_Barrier(MPI_COMM_WORLD);
    vector<double> buff = {vt.get_time(),ps,cm};
    if(rank != 0){
        MPI_Send(buff.data(),3,MPI_DOUBLE,0,0,MPI_COMM_WORLD);
    }else{
        double total_vt = vt.get_time();
        for(int i = 1; i < N; i++){
            MPI_Recv(buff.data(),3,MPI_DOUBLE,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            total_vt += buff[0];
            ps += buff[1];
            cm += buff[2];
        }
        printf("Vt : %lf sec, Ps: %lf KB, Com: %lf MB\n",total_vt,ps+ps_plain,cm/1024.0);
    }
}



void prove_R1CS_standard(size_t size){
    double pt = 0.0,vt = 0.0,ps = 0.0;
    double cm = 0.0;

    vector<F> witness,vL,vO,vR;
    vector<F> RA,RB,RC;
    
    generate_R1CS_matrixes(size);
    
    vector<vector<int>> idx;
    vector<vector<short>> bits;
    logm = (int)log2(size);
    logn = (int)log2(size)+1;

    
    prepare_witness_data(size, witness, vL, vR, vO);
    vector<F> rand_vL = vL,rand_vR = vR,rand_vO = vO;


    vector<F> r1;
    for(int i = 0; i < (int)log2(vL.size()); i++)r1.push_back(F::_random());
    
    
    //_r1 = generate_randomness((int)log2(vL[0].size()));
    //_r2 = generate_randomness((int)log2(k));
    vector<F> beta1,beta2;
    clock_t t1 = clock();
    precompute_beta(r1,beta1);
    
    vector<pair<F,vector<F>>> claims = zerocheck_sumcheck(F(0), beta1, vL, vR,vO,F(0), vt, ps);
    r1 = claims[0].second;
    //vector<F> buff = vL; buff.insert(buff.end(),rL.begin(),rL.end());buff.resize(next_pow2(buff.size()),F(0));
    F a = F::_random(),b= F::_random(),c= F::_random();
    
    
    RA.clear();RB.clear();RC.clear();
    
    reduce_R1CS_matrixes(size,claims[0].second,RA,RB,RC);

    vector<F> R_aggr(RA.size(),F(0));
    
    for(int i = 0; i < RA.size(); i++){
        R_aggr[i] = (a*RA[i] + b*RB[i] + c*RC[i]);
    }
    claims = quadratic_sumcheck(a*claims[1].first+b*claims[2].first+c*claims[3].first, witness, R_aggr,F(0));
    vector<F> r2 = claims[0].second;
    clock_t t2 = clock();
    pt += (double)((t2-t1))/(double)CLOCKS_PER_SEC;
    
    
    printf("Pt: %lf, Vt: %lf, Ps: %lf\n",pt,vt,ps);
    vector<sparse_eval_data> data;
    prepare_R1CS_data(A, B, C, logm, logn, data);
    beta1.clear();beta2.clear();precompute_beta(r1,beta1);precompute_beta(r2,beta2);
    
    witness.clear();
    compute_witness_vector(r1,r2,data,witness,1,pt);
    
    
    prove_sparse_eval(claims[1].first,a,b,c, beta1, beta2, data,pt, ps, vt);
    
    //evaluate_sparse_matrix(size, N, r1, r2, claims[1].first, a, b, c, pt, ps, vt,cm);
    printf("PIOP Perf---- Pt : %lf, Vt: %lf, Ps: %lf KB, Data to commit: (Online): %d, (Offline): %d\n",pt, vt,ps,witness.size(),next_pow2(12*next_pow2(data[0].IDX1.size())));
}







