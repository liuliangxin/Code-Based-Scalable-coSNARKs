#include "coSumcheck_MPI.h"
#include "MPI_utils.hpp"
#include "Fiat_Shamir.h"
extern int queries;



cubic_poly _zero_check_sumcheck_phase1(int iter, F b,vector<F> &v1,vector<F> &v2, vector<F> &v3, vector<F> &beta1, vector<F> &r1, vector<F> &r2){
    quadratic_poly p = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
    quadratic_poly p_r = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
    //quadratic_poly _p = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
    linear_poly _p = linear_poly(F_ZERO,F_ZERO);
    cubic_poly res = cubic_poly(F_ZERO,F_ZERO,F_ZERO,F_ZERO);
    linear_poly l1,l2;
    for(int i = 0; i < v1.size()/(1<<(iter+1)); i++){
        l1 = linear_poly(v1[2*i+1]-v1[2*i],v1[2*i]);
        l2 = linear_poly(v2[2*i+1]-v2[2*i],v2[2*i]);
        p = l1*l2;
        l1 = linear_poly(r1[2*i+1]-r1[2*i],r1[2*i]);
        l2 = linear_poly(r2[2*i+1]-r2[2*i],r2[2*i]);
        p_r = l1*l2;
        _p = linear_poly(v3[2*i+1]-v3[2*i],v3[2*i]);
        p.a = p.a + b*p_r.a ;
        p.b = p.b + b*p_r.b - _p.a;
        p.c = p.c + b*p_r.c - _p.b; 
        res = res + p*linear_poly(beta1[2*i+1]-beta1[2*i],beta1[2*i]);
    }
    return res;
}

void _zero_check_sumcheck_phase2(int iter, F r,vector<F> &v1,vector<F> &v2, vector<F> &v3, vector<F> &beta1, vector<F> &r1, vector<F> &r2){
    for(int i = 0; i < v1.size()/(1<<(iter+1)); i++){
        v1[i] = v1[2*i] + r*(v1[2*i+1]-v1[2*i]);
        v2[i] = v2[2*i] + r*(v2[2*i+1]-v2[2*i]);
        v3[i] = v3[2*i] + r*(v3[2*i+1]-v3[2*i]);
        r1[i] = r1[2*i] + r*(r1[2*i+1]-r1[2*i]);
        r2[i] = r2[2*i] + r*(r2[2*i+1]-r2[2*i]);
        beta1[i] = beta1[2*i] + r*(beta1[2*i+1]-beta1[2*i]);
    }
}

vector<std::pair<F,vector<F>>> _zero_check_sumcheck(F y, vector<F> &v1, 
                                vector<F> &v2, vector<F> &v3, vector<F> &R1, vector<F> &R2, 
                                vector<F> r, int N, int _k, int k, double &pt, double &vt, double &ps, double &cm){  
    int M = v1.size();
    
    vector<F> h1(M,F(0)),h2(M,F(0));
    int j;
    
    for(j = 0; j < R1.size()-2; j++){
        
        h1[1<<j] = R1[j];
        h2[1<<j] = R2[j];
    }
    h1[(1<<j)-2] = R1[j];
    h2[(1<<j)-2] = R2[j];
    h1[(1<<j)-1] = R1[j+1];
    h2[(1<<j)-1] = R2[j+1];
    
    int rounds = (int)log2(M);
    vector<F> challenges(rounds);

    vector<F> _r1,_r2,beta1,beta2;
    


    for(int i = 0; i < (int)log2(k); i++) _r2.push_back(r[i]);
    for(int i = (int)log2(k); i < r.size(); i++) _r1.push_back(r[i]);

    
    precompute_beta(_r1,beta1);precompute_beta(_r2,beta2);
    
    

    F y_r = F_ip_prod(h1,h2,beta1,beta2,k,_k,N);
    
    F b = hash_to_field({y_r});
    
    y += b*y_r;
    
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    
    F sum = F(0);
    for(int i = 0; i < v1.size(); i++){
        sum += v1[i]*v2[i]-v3[i];
    }
    if(sum == F(0)){
        printf(">>OK %d\n",rank);
    }

    for(int i = 0; i < rounds; i++){
        cubic_poly H;
        H = _zero_check_sumcheck_phase1(i, b,v1,v2, v3, beta1, h1, h2);
        H = aggregate_cubic_poly(H,beta2,k,_k,N);
        
        if(H.eval(0) + H.eval(1) != y){
            printf("Error cubic sumcheck %d,(%lld,%lld),(%lld,%lld)\n",i,y.real,y.img,(H.eval(0) + H.eval(1)).real,(H.eval(0) + H.eval(1)).img);
            //exit(-1);
        }
        challenges[i] = hash_to_field({H.a,H.b,H.c,H.d}); 
        
        y = H.eval(challenges[i]);
        
        _zero_check_sumcheck_phase2(i, challenges[i],v1,v2, v3, beta1, h1, h2);
        
    }
    
    
    vector<pair<F,vector<F>>> reply = F_zero_check_rest(v1[0], v2[0], v3[0], h1[0], h2[0], beta1, beta2, b, y, k, _k, N);
    for(int i = 0; i < 4; i++){
        reply[i].second.insert(reply[i].second.end(),challenges.begin(),challenges.end());
    }
    return reply;
}


quadratic_poly _quadratic_batch_sumcheck_phase1(int iter, F b,vector<F> &v1,vector<F> &v2, vector<F> &v3,vector<F> &v4, vector<F> &r1, vector<F> &r2){
    quadratic_poly p = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
    quadratic_poly p_r = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
    linear_poly l1,l2;
    for(int i = 0; i < v1.size()/(1<<(iter+1)); i++){
        l1 = linear_poly(v1[2*i+1]-v1[2*i],v1[2*i]);
        l2 = linear_poly(v2[2*i+1]-v2[2*i],v2[2*i]);
        p = p + l1*l2;
        l1 = linear_poly(v3[2*i+1]-v3[2*i],v3[2*i]);
        l2 = linear_poly(v4[2*i+1]-v4[2*i],v4[2*i]);
        p = p + l1*l2;
        
        l1 = linear_poly(r1[2*i+1]-r1[2*i],r1[2*i]);
        l2 = linear_poly(r2[2*i+1]-r2[2*i],r2[2*i]);
        p_r = p_r + l1*l2;
    }
    p.a = p.a + b*p_r.a;
    p.b = p.b + b*p_r.b;
    p.c = p.c + b*p_r.c;
    return p;
}

void _quadratic_batch_sumcheck_phase2(int iter, F r,vector<F> &v1,vector<F> &v2, vector<F> &v3, vector<F> &v4, vector<F> &r1, vector<F> &r2){
    for(int i = 0; i < v1.size()/(1<<(iter+1)); i++){
        v1[i] = v1[2*i] + r*(v1[2*i+1]-v1[2*i]);
        v2[i] = v2[2*i] + r*(v2[2*i+1]-v2[2*i]);
        v3[i] = v3[2*i] + r*(v3[2*i+1]-v3[2*i]);
        v4[i] = v4[2*i] + r*(v4[2*i+1]-v4[2*i]);
        r1[i] = r1[2*i] + r*(r1[2*i+1]-r1[2*i]);
        r2[i] = r2[2*i] + r*(r2[2*i+1]-r2[2*i]);
    }
}

vector<std::pair<F,vector<F>>> _quadratic_batch_sumcheck(F y, vector<F> &v1, 
                                vector<F> &v2, vector<F> &v3, vector<F> &v4, vector<F> &R1, vector<F> &R2, 
                                int N, int _k, int k, double &pt, double &vt, double &ps, double &cm){  
    int M = v1.size();
    
    vector<F> h1(M,F(0)),h2(M,F(0));
    int j;
    
    for(j = 0; j < R1.size()-2; j++){
        
        h1[1<<j] = R1[j];
        h2[1<<j] = R2[j];
    }
    h1[(1<<j)-2] = R1[j];
    h2[(1<<j)-2] = R2[j];
    h1[(1<<j)-1] = R1[j+1];
    h2[(1<<j)-1] = R2[j+1];
    
    int rounds = (int)log2(M);
    vector<F> challenges(rounds);

    vector<F> _r1,_r2,ones1(M,F(1)),ones2(k,F(1));

    F y_r = F_ip_prod(h1,h2,ones1,ones2,k,_k,N);
    
    F b = hash_to_field({y_r});
    
    y += b*y_r;
    
    //printf("%d,%d,%d,%d\n",v1.size(),v2.size(),v3.size(),v4.size());
    for(int i = 0; i < rounds; i++){
        quadratic_poly H;
        H = _quadratic_batch_sumcheck_phase1(i, b,v1,v2, v3,v4, h1, h2);
        H = aggregate_quadratic_poly(H,k,_k,N);
        
        if(H.eval(0) + H.eval(1) != y){
            printf("Error cubic sumcheck %d,(%lld,%lld),(%lld,%lld)\n",i,y.real,y.img,(H.eval(0) + H.eval(1)).real,(H.eval(0) + H.eval(1)).img);
            //exit(-1);
        }
        challenges[i] = hash_to_field({H.a,H.b,H.c}); 
        
        y = H.eval(challenges[i]);
        
        _quadratic_batch_sumcheck_phase2(i, challenges[i],v1,v2, v3, v4, h1, h2);
        
    }
    
    
    vector<pair<F,vector<F>>> reply = F_batch_sumcheck_rest(v1[0], v2[0], v3[0], v4[0], h1[0], h2[0], b, y, k, _k, N);
    for(int i = 0; i < 4; i++){
        reply[i].second.insert(reply[i].second.end(),challenges.begin(),challenges.end());
    }
    return reply;
}