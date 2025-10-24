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
#include "coSumcheck_MPI.h"
#include "coPCS_utils.h"
#include <mpi.h>
#include "coPCS.h"
#include "Fiat_Shamir.h"
#include "Distributed_Sumcheck.h"
#include "MPI_utils.hpp"
#include "timer.hpp"
#include <algorithm>
int tensor_row_size;
int mul_counter= 0;

extern vector<vector<pair<int, int>>> A,B,C;
extern vector<vector<pair<int, int>>> pA,pB,pC;
extern int logm,logn;



void encode_locally(vector<vector<F>> &C, vector<vector<F>> &R_shares, int l, int N, int M, int k, int _k){
    vector<vector<F>> data(M/k);
    C.resize(N);
    int ctr = 0;
    for(int i = 0; i < data.size(); i++){
        data[i].resize(_k);
        for(int j = 0; j < _k; j++){
            data[i][j] = ctr++;
        }
        fft(data[i],(int)log2(_k),true);
        data[i].resize(N,0);
        fft(data[i],(int)log2(N),false);
    }
    for(int i = 0; i < C.size(); i++){
        C[i].resize(next_pow2(M/k+l),F(0));
        for(int j = 0; j < M/k; j++){
            C[i][j] = data[j][i];
        }
        for(int j = 0; j < l; j++){
            C[i][j+(M/k)] = R_shares[i][j];
        }
        fft(C[i], (int)log2(C[i].size()),true);
        C[i].resize(C[i].size()*4,F(0));
        fft(C[i], (int)log2(C[i].size()),false);
        
    }
}   

F evaluate_locally(vector<F> r, int k, int _k){
    vector<F> b;precompute_beta(r,b);
    F y = F(0);
    int ctr = 0;
    int idx = 0;
    for(int i = 0; i < b.size()/k; i++){
        for(int j = 0; j < k; j++){
            y += b[idx]*F(ctr);
            ctr++;
            idx++;
        }
        ctr += (_k-k);    
    }
    return y;
}


void test_batch_check(int M,int N, int k, int _k, int l){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<vector<F>> V1(N),V2(N),V3(N),V4(N); 
    vector<vector<F>> R1(N),R2(N); 
    vector<F> r;
    for(int i = 0; i < (int)log2(M); i++){
        r.push_back(hash_to_field({0}));
    }   
    vector<F> fl,fr,fo;
    F y = F(0);
    if(rank == 0){
       //vector<F> beta; precompute_beta(r,beta);
        int idx = 0;
        for(int i = 0; i < N; i++){
            V1[i].resize(M/k);V2[i].resize(M/k);V3[i].resize(M/k);V4[i].resize(M/k);
            R1[i].resize((int)log2(M/k) + 2 );
            R2[i].resize((int)log2(M/k) + 2 );
        }
        int ctr = 0;
        
        for(int i = 0; i < M/k; i++){
            vector<F> buff1(_k),buff2(_k),buff3(_k),buff4(_k);
            for(int j = 0; j < k; j++){
                buff1[j] = ctr++;
                buff2[j] = ctr++;
                buff3[j] = ctr++;                
                buff4[j] = ctr++;                
                y += buff1[j]*buff2[j] + buff3[j]*buff4[j];
                fl.push_back(buff1[j]);
                fr.push_back(buff2[j]);
                fo.push_back(buff3[j]);
            }
            for(int j = k; j < _k; j++){
                buff1[j] = ctr++;
                buff2[j] = ctr++;
                buff3[j] = ctr++;                
                buff4[j] = ctr++;                
            }
            fft(buff1,(int)log2(buff1.size()),true);fft(buff2,(int)log2(buff2.size()),true);fft(buff3,(int)log2(buff3.size()),true);fft(buff4,(int)log2(buff4.size()),true);
            buff1.resize(2*N,0);buff2.resize(2*N,0);buff3.resize(2*N,0);buff4.resize(2*N,0);
            fft(buff1,(int)log2(buff1.size()),false);fft(buff2,(int)log2(buff2.size()),false);fft(buff3,(int)log2(buff3.size()),false);
            fft(buff4,(int)log2(buff4.size()),false);
            for(int j = 0; j < N; j++){
                V1[j][i] = buff1[2*j+1];
                V2[j][i] = buff2[2*j+1];
                V3[j][i] = buff3[2*j+1];
                V4[j][i] = buff4[2*j+1];
            }
        }
        
        for(int i = 0; i < R1[0].size(); i++){
            vector<F> buff1(_k),buff2(_k);
            for(int j = 0; j < k; j++){
                buff1[j] = ctr++;
                buff2[j] = ctr++;
            }
            for(int j = k; j < _k; j++){
                buff1[j] = ctr++;
                buff2[j] = ctr++;
            }
            fft(buff1,(int)log2(buff1.size()),true);fft(buff2,(int)log2(buff2.size()),true);
            buff1.resize(2*N,0);buff2.resize(2*N,0);
            fft(buff1,(int)log2(buff1.size()),false);fft(buff2,(int)log2(buff2.size()),false);
            for(int j = 0; j < N; j++){
                R1[j][i] = buff1[2*j+1];
                R2[j][i] = buff2[2*j+1];
            }
        }
        
    }
    vector<F> v1,v2,v3,v4,h1,h2;
    vector<F> buff;
    vector<u64> buff_u64;
    
    if(rank == 0){
        v1 = V1[0];v2 = V2[0]; v3 = V3[0]; v4 = V4[0];
        h1 = R1[0]; h2 = R2[0];
        for(int i = 1; i < N; i++){
            buff = V1[i];
            buff.insert(buff.end(),V2[i].begin(),V2[i].end());
            buff.insert(buff.end(),V3[i].begin(),V3[i].end());
            buff.insert(buff.end(),V4[i].begin(),V4[i].end());
            buff.insert(buff.end(),R1[i].begin(),R1[i].end());
            buff.insert(buff.end(),R2[i].begin(),R2[i].end());
            buff.push_back(y);
            field_vector_serialize(buff,buff_u64);
            MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        }
    }else{
        buff_u64.resize(2+2*(4*M/k + 2*(log2(M/k) + 2)));
        MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        field_vector_deserialize(buff_u64,buff);
        v1.resize(M/k);v2.resize(M/k);v3.resize(M/k);v4.resize(M/k);
        h1.resize(log2(M/k) + 2);h2.resize(log2(M/k) + 2);
        int ctr = 0;
        for(int i = 0; i < M/k; i++){
            v1[i] = buff[ctr++];
        }
        for(int i = 0; i < M/k; i++){
            v2[i] = buff[ctr++];
        }
        for(int i = 0; i < M/k; i++){
            v3[i] = buff[ctr++];
        }
        for(int i = 0; i < M/k; i++){
            v4[i] = buff[ctr++];
        }
        for(int i = 0; i < h1.size(); i++){
            h1[i] = buff[ctr++];
        }
        for(int i = 0; i < h1.size(); i++){
            h2[i] = buff[ctr++];
        }
        y = buff[ctr];
    }
    MPI_Barrier(MPI_COMM_WORLD);

    double pt = 0.0,vt = 0,ps = 0,cm = 0;
    vector<pair<F,vector<F>>> reply = _quadratic_batch_sumcheck(y, v1, v2, v3,v4, h1, h2, N, _k, k,ps);
    if(rank == (0)){
        if(evaluate_vector(fl,reply[0].second) != reply[0].first){
            printf("ERROR L\n");
        }
        if(evaluate_vector(fr,reply[1].second) != reply[1].first){
            printf("ERROR R\n");
        }
        if(evaluate_vector(fo,reply[2].second) != reply[2].first){
            printf("ERROR O\n");
        }
        printf("OK\n");
    }

}

void test_zero_check(int M,int N, int k, int _k, int l){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<vector<F>> L(N),R(N),O(N); 
    vector<vector<F>> R1(N),R2(N); 
    vector<F> r;
    for(int i = 0; i < (int)log2(M); i++){
        r.push_back(hash_to_field({0}));
    }   
    vector<F> fl,fr,fo;
        
    if(rank == 0){
       //vector<F> beta; precompute_beta(r,beta);
        int idx = 0;
        for(int i = 0; i < N; i++){
            L[i].resize(M/k);R[i].resize(M/k);O[i].resize(M/k);
            R1[i].resize((int)log2(M/k) + 2 + l);
            R2[i].resize((int)log2(M/k) + 2 + l);
        }
        int ctr = 0;

        for(int i = 0; i < M/k; i++){
            vector<F> buffL(_k),buffR(_k),buffO(_k);
            for(int j = 0; j < k; j++){
                buffL[j] = ctr++;
                buffR[j] = ctr++;
                buffO[j] = buffL[j]*buffR[j];                
                fl.push_back(buffL[j]);
                fr.push_back(buffR[j]);
                fo.push_back(buffO[j]);
            }
            for(int j = k; j < _k; j++){
                buffL[j] = ctr++;
                buffR[j] = ctr++;
                buffO[j] = ctr++;                
            }
            fft(buffL,(int)log2(buffL.size()),true);fft(buffR,(int)log2(buffL.size()),true);fft(buffO,(int)log2(buffL.size()),true);
            buffL.resize(2*N,0);buffR.resize(2*N,0);buffO.resize(2*N,0);
            fft(buffL,(int)log2(buffL.size()),false);fft(buffR,(int)log2(buffL.size()),false);fft(buffO,(int)log2(buffL.size()),false);
            for(int j = 0; j < N; j++){
                L[j][i] = buffL[2*j+1];
                R[j][i] = buffR[2*j+1];
                O[j][i] = buffO[2*j+1];
            }
        }
        
        for(int i = 0; i < R1[0].size(); i++){
            vector<F> buff1(_k),buff2(_k);
            for(int j = 0; j < k; j++){
                buff1[j] = ctr++;
                buff2[j] = ctr++;
            }
            for(int j = k; j < _k; j++){
                buff1[j] = ctr++;
                buff2[j] = ctr++;
            }
            fft(buff1,(int)log2(buff1.size()),true);fft(buff2,(int)log2(buff2.size()),true);
            buff1.resize(2*N,0);buff2.resize(2*N,0);
            fft(buff1,(int)log2(buff1.size()),false);fft(buff2,(int)log2(buff2.size()),false);
            for(int j = 0; j < N; j++){
                R1[j][i] = buff1[2*j+1];
                R2[j][i] = buff2[2*j+1];
            }
        }
        
    }
    vector<F> v1,v2,v3,h1,h2;
    vector<F> buff;
    vector<u64> buff_u64;
    
    if(rank == 0){
        v1 = L[0];v2 = R[0]; v3 = O[0];
        h1 = R1[0]; h2 = R2[0];
        for(int i = 1; i < N; i++){
            buff = L[i];
            buff.insert(buff.end(),R[i].begin(),R[i].end());
            buff.insert(buff.end(),O[i].begin(),O[i].end());
            buff.insert(buff.end(),R1[i].begin(),R1[i].end());
            buff.insert(buff.end(),R2[i].begin(),R2[i].end());
            field_vector_serialize(buff,buff_u64);
            MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        }
    }else{
        buff_u64.resize(2*(3*M/k + 2*(log2(M/k) + 2+l)));
        MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        field_vector_deserialize(buff_u64,buff);
        v1.resize(M/k);v2.resize(M/k);v3.resize(M/k);
        h1.resize(log2(M/k) + 2+l);h2.resize(log2(M/k) + 2+l);
        int ctr = 0;
        for(int i = 0; i < M/k; i++){
            v1[i] = buff[ctr++];
        }
        for(int i = 0; i < M/k; i++){
            v2[i] = buff[ctr++];
        }
        for(int i = 0; i < M/k; i++){
            v3[i] = buff[ctr++];
        }
        for(int i = 0; i < h1.size(); i++){
            h1[i] = buff[ctr++];
        }
        for(int i = 0; i < h1.size(); i++){
            h2[i] = buff[ctr++];
        }
    }
    MPI_Barrier(MPI_COMM_WORLD);

    double pt = 0.0,vt = 0,ps = 0,cm = 0;
    vector<pair<F,vector<F>>> reply = _zero_check_sumcheck(F(0), v1, v2, v3, h1, h2, r, N, _k, k,ps);
    if(rank == (0)){
        if(evaluate_vector(fl,reply[0].second) != reply[0].first){
            printf("ERROR L\n");
        }
        if(evaluate_vector(fr,reply[1].second) != reply[1].first){
            printf("ERROR R\n");
        }
        if(evaluate_vector(fo,reply[2].second) != reply[2].first){
            printf("ERROR O\n");
        }
        printf("OK\n");
    }

}

void distribute_data(vector<vector<F>> &Data){
    vector<u64> buff;
    for(int i = 1; i < Data.size(); i++){
        field_vector_serialize(Data[i],buff);
        MPI_Send(buff.data(),buff.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD);
    }
}

void distribute_data_tensor(vector<vector<vector<F>>> &Data){
    vector<u64> buff;
    vector<F> arr;
    for(int i = 1; i < Data.size(); i++){
        arr = convert2vector(Data[i]);
        field_vector_serialize(arr,buff);
        MPI_Send(buff.data(),buff.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD);
    }
}

void get_data(vector<F> &v, int N){
    vector<u64> buff(N*2);
    MPI_Recv(buff.data(),buff.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
    field_vector_deserialize(buff,v);
}

void test_quadratic_sumheck(int N, int M){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    F sum = 0;
    vector<F> arr1,arr2;
    vector<F> f1,f2;
    if(rank == 0){
        vector<vector<F>> V(N);
        vector<vector<F>> v1(N),v2(N);
        for(int i = 0; i < N; i++){
            v1[i].resize(M/N);
            v2[i].resize(M/N);
            for(int j = 0; j < v1[i].size(); j++){
                v1[i][j] = random();
                v2[i][j] = random();
                f1.push_back(v1[i][j]);
                f2.push_back(v2[i][j]);
                
                sum += v1[i][j]*v2[i][j];
            }
            V[i] = v1[i];
            V[i].insert(V[i].end(),v2[i].begin(),v2[i].end());
        }
        for(int i = 0; i < N; i++){
            V[i].push_back(sum);
        }
        arr1 = v1[0];
        arr2 = v2[0];
        distribute_data(V);
    }else{
        vector<F> buff;
        get_data(buff,2*M/N+1);
        arr1.resize(M/N);
        arr2.resize(M/N);
        for(int i = 0; i < M/N; i++){
            arr1[i] = buff[i];
            arr2[i] = buff[i+M/N];
        }
        sum = buff[buff.size()-1];
    }
    double vt = 0.0,ps = 0.0;
    vector<pair<F,vector<F>>> claims = _quadratic_sumcheck(sum, arr1, arr2, N);
    if(rank == 0){
        if(evaluate_vector(f1,claims[0].second) != claims[0].first){
            printf("ERROR1\n");
        }
        if(evaluate_vector(f1,claims[0].second) != claims[0].first){
            printf("ERROR1\n");
        }
    }
    
}

void test_cubic_sumheck(int N, int M){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    F sum = 0;
    vector<F> arr1,arr2,arr3;
    if(rank == 0){
        vector<vector<F>> V(N);
        vector<vector<F>> v1(N),v2(N),v3(N);
        for(int i = 0; i < N; i++){
            v1[i].resize(M/N);
            v2[i].resize(M/N);
            v3[i].resize(M/N);
            for(int j = 0; j < v1[i].size(); j++){
                v1[i][j] = random();
                v2[i][j] = random();
                v3[i][j] = random();
                sum += v1[i][j]*v2[i][j]*v3[i][j];
            }
            V[i] = v1[i];
            V[i].insert(V[i].end(),v2[i].begin(),v2[i].end());
            V[i].insert(V[i].end(),v3[i].begin(),v3[i].end());
        }
        for(int i = 0; i < N; i++){
            V[i].push_back(sum);
        }
        arr1 = v1[0];
        arr2 = v2[0];
        arr3 = v3[0];
        distribute_data(V);
    }else{
        vector<F> buff;
        get_data(buff,3*M/N+1);
        arr1.resize(M/N);
        arr2.resize(M/N);
        arr3.resize(M/N);
        for(int i = 0; i < M/N; i++){
            arr1[i] = buff[i];
            arr2[i] = buff[i+M/N];
            arr3[i] = buff[i+2*M/N];
        }
        sum = buff[buff.size()-1];
    }
    double vt = 0.0,ps = 0.0;
    //_cubic_sumcheck(sum, arr1, arr2, arr3, N, vt, ps);
    
}

void test_product(int N, int M, int K){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<vector<F>> input(K);
    vector<F> prod(K,F(1));
    vector<vector<vector<F>>> data(N);
    vector<vector<F>> poly_matrix(K);
    if(rank == 0){
        int ctr = 1;
        for(int i = 0; i < N; i++){
            data[i].resize(K);
            for(int j = 0; j < K; j++){
                data[i][j].resize(M/N);
                for(int k = 0; k < M/N; k++){
                    data[i][j][k] = ctr++;
                    prod[j] *= data[i][j][k];
                    poly_matrix[j].push_back(data[i][j][k]);
                } 
            }
        }
        input = data[0];
        distribute_data_tensor(data);
    }else{
        vector<F> buff;
        int ctr = 0;
        get_data(buff,K*M/N);
        for(int i = 0; i < input.size(); i++){
            input[i].resize(M/N);
            for(int j = 0; j < M/N; j++){
                input[i][j] = buff[ctr++];
            }
        }
    }

    vector<F> output,r;
    double vt,ps;
    
    pair<F,vector<vector<F>>> claim =  prove_product(input, output, F(0), r, N);
    
    vector<F> b1,b2;
    precompute_beta(claim.second[0],b1);
    precompute_beta(claim.second[2],b2);
    vector<F> Y = batch_distributed_eval(input,b1,b2,N);
    
    if(rank == 0){
        F sum  =F(0);
        for(int i = 0; i < data.size(); i++){
            F y = F(0);
            for(int j = 0; j < data[i][0].size(); j++){
                if(i == 0 && data[i][0][j] != input[i][j]){
                    printf("Error\n");
                }
                y += data[i][0][j]*b1[j];
            }
            printf("> %lld,%lld\n",y.real,y.img);
            sum += b2[i]*y;
        }

        printf("%d\n",output.size());
        for(int i = 0; i < output.size(); i++){
            if(output[i] != prod[i]){
                printf("Error %d\n",i);
            }
        }
        for(int i = 0; i < input.size(); i++){
            for(int j = 0; j < input[i].size(); j++){
                if(input[i][j] != poly_matrix[i][j]){
                    printf("Error\n");
                }
            }
        }
        vector<F> r = claim.second[0];
        r.insert(r.end(),claim.second[2].begin(),claim.second[2].end());
        r.insert(r.end(),claim.second[1].begin(),claim.second[1].end());
        vector<F> poly = convert2vector(poly_matrix);
        if(evaluate_vector(poly,r) != claim.first){
            printf(">>>EEROR\n");
        }
        if(sum != claim.first){
            printf("EEER\n");
        }
        if(evaluate_vector(Y,claim.second[1])!= sum){
            printf("EERROR 2\n");
        }
    }
}





void test_sparse_eval(int N, int M){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<sparse_eval_data> index;
        
    distribute_index(N, M, index);
    
    vector<F> r1,r2;
    vector<vector<F>> beta1(3),beta2(3);
    F a = hash_to_field({0}), b = hash_to_field({0}), c = hash_to_field({0});
    double pt = 0.0;

    for(int i = 0; i < logm; i++){
        r1.push_back(hash_to_field({0}));
    }
    for(int i = 0; i < logn; i++){
        r2.push_back(hash_to_field({0}));
    }

    compute_R1CS_betas(r1,  r2, index, beta1, beta2, logm, logn, N);
    vector<F> RA,RB,RC;
    _reduce_R1CS_matrixes(M, r1, RA, RB, RC, N);
    
    
    
    vector<vector<F>> polys = {RA,RB,RC};
    vector<F> r21,r22;
    for(int i = 0; i < logn - (int)log2(N); i++) r21.push_back(r2[i]);
    for(int i = r21.size(); i < r2.size(); i++) r22.push_back(r2[i]);
    vector<F> b1,b2;
    precompute_beta(r21,b1);precompute_beta(r22,b2);
    

    vector<F> Y = batch_distributed_eval(polys,b1,b2,N);
    vector<F> _RA,_RB,_RC;
    if(rank!= 0){
        generate_R1CS_matrixes(M);
    }
    
    reduce_R1CS_matrixes(M,r1,_RA,_RB,_RC);
      
        for(int i = 0; i < RA.size(); i++){
            if(RA[i] != _RA[i + rank*pA.size()]){
               printf("Error %d,%d, (%lld,%lld),(%lld,%lld)\n",i,RB.size(),RA[i].real,RA[i].img,_RA[i + rank*pB.size()].real,_RA[i + rank*pB.size()].img);
            }
        }
        for(int i = 0; i < RB.size(); i++){
            if(RB[i] != _RB[i + rank*pB.size()]){
               printf("Error %d,%d, (%lld,%lld),(%lld,%lld)\n",i,RB.size(),RA[i].real,RA[i].img,_RA[i + rank*pB.size()].real,_RA[i + rank*pB.size()].img);
            }
        }

        for(int i = 0; i < RC.size(); i++){
            if(RC[i] != _RC[i + rank*pC.size()]){
               printf("Error %d,%d, (%lld,%lld),(%lld,%lld)\n",i,RB.size(),RA[i].real,RA[i].img,_RA[i + rank*pB.size()].real,_RA[i + rank*pB.size()].img);
            }
        }
        if(evaluate_vector(_RA,r2) != Y[0]){
            printf("Error 1\n");
        }
        if(evaluate_vector(_RB,r2) != Y[1]){
            printf("Error 2\n");
        }
        if(evaluate_vector(_RC,r2) != Y[2]){
            printf("Error 3\n");
        }
    
    MPI_Barrier(MPI_COMM_WORLD);
    //_prove_sparse_eval(a*Y[0]+b*Y[1]+c*Y[2], a, b, c, beta1, beta2, index,r1,r2, N, pt, pt, pt);
    _prove_sparse_eval_opt(a*Y[0]+b*Y[1]+c*Y[2], a, b, c, beta1, beta2, index, r1, r2, N);
}

void test_mult_tree(vector<int> dims, int N){
    int rank,size = 0;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<F> output;
    for(int i = 0; i < dims.size(); i++) size += dims[i];
    vector<vector<F>> input;
    vector<F> prod(dims.size(),F(1));
    if(rank == 0){
        vector<vector<vector<F>>> data(N);
        for(int i = 0; i < N; i++){
            data[i].resize(dims.size());
            for(int j = 0; j < dims.size(); j++){
                data[i][j] = generate_randomness(dims[j]/N);
                for(int k = 0; k < data[i][j].size(); k++) prod[j] *= data[i][j][k];
            }
        }
        input = data[0];
        distribute_data_tensor(data);
    }else{
        vector<F> v;
        get_data(v,size/N);
        input.resize(dims.size());
        int ctr = 0;
        for(int i = 0; i < dims.size(); i++){
            input[i].resize(dims[i]/N);
            for(int j = 0; j < input[i].size(); j++) input[i][j] = v[ctr++];
        }
    }
    prove_product_opt(input, output, N);
    if(rank == 0){
        for(int i = 0; i < output.size(); i++){
            if(output[i] != prod[i]){
                printf("Error %d\n",i);
            }
        }
    }
}



int main(int argc, char *argv[]){
    
    
    
  
    
    int K = 1<<atoi(argv[1]);
    int N = atoi(argv[2]);
    int k = N/4;
    int _k = N/2;
    int M = 1ULL<<(atoi(argv[3]));
    int size;
    int rank;
    


    //encode_locally(C,R_shares,500,N,M,k,_k);
    MPI_Init (&argc, &argv);
    
    MPI_Comm_size(MPI_COMM_WORLD, &size); //get number of processes
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    double vt = 0.0,ps = 0.0;
    vector<F> codeword,row_data;
    vector<vector<F>> data;
    MT Com;
    vector<vector<F>> mask_shares,mask_data,C_mask;
    vector<F> R_shares;
    vector<MT> Com_mask;
    
    
    //vector<int> dims = {1<<16,1<<14,1<<14};
    //test_mult_tree(dims, N);
    
    test_sparse_eval(N, M);
    
    
    //coPIOP_prove(M, N, _k, k);
    
    // ==================================================== //
    /*
    dummy_setup(R_shares, mask_shares, N, M, k, _k, 500);

    prepare_mask_shares(mask_shares, mask_data, C_mask, Com_mask, N, M, k, _k, 500);
    commit(codeword,row_data,R_shares,Com,500,k,_k,M,N);
    open_zk(codeword, C_mask, row_data, mask_data, Com, Com_mask, r, y, 500, k, _k, M, N,ps,vt);
    */
    
    
    if (rank == 0) printf("MPI World size = %d processes\n", size);
    //else printf("Worker Finalizing ... \n");
    MPI_Finalize();
    
    /*
    if(op == 1){
        prove_R1CS(size,N,_k,k);
    }else if(op == 2){
        prove_R1CS_standard(size);    
    }else if(op == 3){
        emulate_PCS(size,N,k,_k,ps);
    }
    exit(-1);
    */
    
    return 0;
}
