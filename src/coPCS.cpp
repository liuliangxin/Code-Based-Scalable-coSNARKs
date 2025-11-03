#include "coPCS.h"
#include "Fiat_Shamir.h"
#include "Distributed_Sumcheck.h"
#include "timer.hpp"
extern int rate;
extern timer pt_cp,vt;
extern double cm;
extern int com_rounds;
extern int PC_offset;

void distributed_MT(vector<F> &data, MT &Com, int N){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    pt_cp.start();
    merkle_tree::merkle_tree_prover::MT_commit_Blake(data.data(),Com.Base_MT, data.size());
    pt_cp.end();
    com_rounds++;
    if(rank != 0){
        
        MPI_Send(Com.Base_MT[Com.Base_MT.size()-1][0].arr,32,MPI_UINT8_T,0,0,MPI_COMM_WORLD);
    }else{
        vector<_hash> recv_hashes(N);
        recv_hashes[0] = Com.Base_MT[Com.Base_MT.size()-1][0];
        for(int i = 1; i < N; i++){
            MPI_Recv(recv_hashes[i].arr,32,MPI_UINT8_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);            
        }
        Com.Root_MT.resize((int)log2(N)+1);
        Com.Root_MT[0] = recv_hashes;
        merkle_tree::merkle_tree_prover::create_tree_blake(N,Com.Root_MT,sizeof(__hhash_digest),true);
    }
}

void dummy_setup(vector<F> &R_shares, vector<vector<F>> &mask_shares, int N, int M, int k, int _k, int l){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
     
    //emulate_setup(R,mask_data,C_mask,C_mask_hashes,M,N,k,_k,500);
    vector<u64> buff; 
    if(rank == 0){
        vector<vector<F>> encode_shares;
        setup(encode_shares,N,M,l,k,_k);
        encode_shares = transpose(encode_shares);
        R_shares = encode_shares[0];
        
        for(int i = 1; i < N; i++){
            field_vector_serialize(encode_shares[i],buff);
            cm += 8*buff.size()/1024.0;
            MPI_Send(buff.data(),buff.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        }
    }else{
        buff.resize(2*l);
        MPI_Recv(buff.data(),2*l,MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        field_vector_deserialize(buff,R_shares);
    }


    if((int)log2(M/k)-1 <= (int)log2(next_pow2(l))){
        //printf(">>>OK\n");
        mask_shares.resize(1);
        if(rank == 0){
            vector<vector<vector<F>>> all_mask_shares(1);
            setup(all_mask_shares[0],N,M,2*M/k,k,_k);
            all_mask_shares[0] = transpose(all_mask_shares[0]);
            mask_shares[0] = all_mask_shares[0][0];
            for(int i = 1; i < N; i++){
                field_vector_serialize(all_mask_shares[0][i],buff);    
                cm += 8*buff.size()/1024.0;        
                MPI_Send(buff.data(),buff.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD);
            }
        }else{
            buff.clear();buff.resize(2*(2*M/k));
            MPI_Recv(buff.data(),2*(2*M/k),MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            field_vector_deserialize(buff,mask_shares[0]);
        }
        
    }else{
        mask_shares.resize((int)log2(M/k)-1-(int)log2(l));
        if(rank == 0){
            vector<vector<vector<F>>> all_mask_shares(mask_shares.size());
            for(int i = 0; i < mask_shares.size(); i++){
                if(i != mask_shares.size()-1){
                    setup(all_mask_shares[i],N,M,3*l+2,k,_k);
                }else{
                    setup(all_mask_shares[i],N,M,next_pow2(3*l+M/k)/(1<<i),k,_k);
                }
                all_mask_shares[i] = transpose(all_mask_shares[i]);
                mask_shares[i] = all_mask_shares[i][0];
                
                for(int j = 1; j < N; j++){
                    field_vector_serialize(all_mask_shares[i][j],buff);      
                    cm += 8*buff.size()/1024.0;      
                    MPI_Send(buff.data(),buff.size(),MPI_UINT64_T,j,0,MPI_COMM_WORLD);
                }
            }
        }else{
            for(int i = 0; i < mask_shares.size(); i++){
                if(i != mask_shares.size()-1){
                    buff.clear();buff.resize(2*(3*l + 2));
                    MPI_Recv(buff.data(),2*(3*l + 2),MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
                    field_vector_deserialize(buff,mask_shares[i]);
                }else{
                    buff.clear();buff.resize(2*next_pow2(3*l+M/k)/(1<<i));
                    MPI_Recv(buff.data(),2*(3*l + M/k),MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
                    field_vector_deserialize(buff,mask_shares[i]);
                }                
            }
        }
    }

}


void commit_randomness(vector<F> R, vector<F> _R, vector<F> &codeword, vector<F> &_codeword, MT &CR, MT &_CR, int N){
    codeword = R;codeword.resize(2*next_pow2(R.size()),F(0));
    _codeword = _R;_codeword.resize(2*next_pow2(_R.size()),F(0));
    fft(codeword,(int)log2(codeword.size()),false);
    fft(_codeword,(int)log2(_codeword.size()),false);
    distributed_MT(codeword,CR,N);
    distributed_MT(_codeword,_CR,N);
}


void prepare_mask_shares(vector<vector<F>> &mask_shares, vector<vector<F>> &mask_data, vector<vector<F>> &C_mask, vector<MT> &Com_mask, int N, int M, int k, int _k, int l){
    C_mask.resize(mask_shares.size());
    Com_mask.resize(mask_shares.size());
    mask_data.resize(mask_shares.size());
    

    for(int i = 0; i < C_mask.size(); i++){
        //C_mask_hashes[i].resize(C_mask[i].size());
        if(i != C_mask.size()-1){
            C_mask[i].resize(next_pow2(M/k+3*l)/(1<<i),F(0));
            C_mask[i][0] = mask_shares[i][0];
            C_mask[i][1] = mask_shares[i][1];
            for(int b = 0; b < 3*l; b++){
                C_mask[i][C_mask[i].size()/2 + b] = mask_shares[i][b+2];
            }
            
        }else{
            if(C_mask.size() == 1 && (int)log2(M/k)-1 <= (int)log2(next_pow2(l))){
                C_mask[i].resize(mask_shares[i].size(),F(0));
            }else{
                C_mask[i].resize(next_pow2(M/k+3*l)/(1<<i),F(0));
            }

            for(int b = 0; b < mask_shares[i].size(); b++){
                C_mask[i][b] = mask_shares[i][b];
            }
        }
        
        fft(C_mask[i],(int)log2(C_mask[i].size()),true);
        mask_data[i] = C_mask[i];
        C_mask[i].resize(C_mask[i].size()*rate,F(0));
        fft(C_mask[i],(int)log2(C_mask[i].size()),false);
        
        
        distributed_MT(C_mask[i], Com_mask[i],N);
    }

    // ADD SYNCH Barrier
    MPI_Barrier(MPI_COMM_WORLD);

}

void get_data(vector<vector<F>> &data, int N , int id, int k, int _k, int M){
    data.resize(M/(k));
    int ctr = id*M*_k/k;
    for(int i = 0; i < M/(k); i++){
        data[i].resize(_k);
        for(int j = 0; j < k; j++){
            // Initialize actual secret data
            data[i][j] = ctr++;
        }
        for(int j = k; j < _k; j++){
            data[i][j] = ctr++;
        }
    }
}


void encode(vector<F> &codeword, vector<F> &row_data, vector<vector<F>> &data, vector<F> &R_shares, int l, int k, int _k, int M, int N){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    
    MPI_Request request;
    vector<vector<F>> shares(M/(N*k));
    
    for(int i = 0; i < data.size(); i++){
        shares[i] = data[i];
        fft(shares[i],(int)log2(shares[i].size()),true);
        shares[i].resize(N,F(0));
        fft(shares[i],(int)log2(shares[i].size()),false);
    }
    vector<F> row(shares.size());
    shares = transpose(shares);
    //printf("Shares Dim : %d,%d\n",shares.size(),shares[0].size());
    vector<F> shares_v = convert2vector(shares);
    vector<u64> send_buff,recv_buff;
    
    field_vector_serialize(shares_v,send_buff);
    recv_buff.resize(send_buff.size());
    cm += 8*send_buff.size()/1024.0;        
    com_rounds++;
    MPI_Alltoall(send_buff.data(),send_buff.size()/N,MPI_UINT64_T,recv_buff.data(),recv_buff.size()/N,MPI_UINT64_T,MPI_COMM_WORLD);

    field_vector_deserialize(recv_buff,row);

    row_data.resize(next_pow2(row.size()+l),0);
    // Input distribution emulation 
    //printf(">> %d\n",row.size());
    for(int j = 0; j < row.size(); j++){
        row_data[j] = row[j];
    }
    for(int j = 0 ; j < l; j++){
        row_data[j + row.size()] = R_shares[j]; 
    }
    encode_protocol_step2(row, R_shares, codeword);
}



void commit(vector<F> &codeword, vector<F> &row_data, vector<F> &R_shares, MT &Com, int l, int k, int _k, int M, int N){
    int rank;
    vector<vector<F>> data;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    get_data(data,N,rank,k,_k,M/N);
    encode(codeword,row_data,data,R_shares,l,k,_k,M,N);
    distributed_MT(codeword, Com,N);
}
// Commitment algorithm when given the secret shares
void commit(vector<F> &codeword, vector<F> &row_data, vector<F> &W_shares, vector<F> &R_shares, MT &Com, int l, int k, int _k, int N){
    pt_cp.start();
    row_data.resize(next_pow2(W_shares.size()+l),0);
    // Input distribution emulation 
    //printf(">> %d\n",row.size());
    for(int j = 0; j < W_shares.size(); j++){
        row_data[j] = W_shares[j];
    }
    for(int j = 0 ; j < l; j++){
        row_data[j + W_shares.size()] = R_shares[j]; 
    }
    encode_protocol_step2(W_shares, R_shares, codeword);
    pt_cp.end();
    distributed_MT(codeword, Com,N);
}


void plaintext_commit(vector<F> &data, vector<F> &codeword ,vector<F> &row_data, MT &Com, int k, int N){
    pt_cp.start();
    vector<vector<F>> matrix_data(N);
    for(int i = 0; i < N; i++){
        matrix_data[i].resize(data.size()/k);
    }
    int ctr = 0;
    for(int i = 0; i < data.size()/k; i++){
        vector<F> buff(N,F(0));
        for(int j = 0; j < k; j++) buff[j] = data[ctr++];
        fft(buff,(int)log2(N),false);
        for(int j = 0; j < N; j++) matrix_data[j][i] = buff[j];
    }
    
    vector<F> shares_v = convert2vector(matrix_data);
    vector<u64> send_buff,recv_buff;
    
    field_vector_serialize(shares_v,send_buff);
    recv_buff.resize(send_buff.size());
    pt_cp.end();
    cm += 8*send_buff.size()/1024.0;        
    com_rounds++;
    MPI_Alltoall(send_buff.data(),send_buff.size()/N,MPI_UINT64_T,recv_buff.data(),recv_buff.size()/N,MPI_UINT64_T,MPI_COMM_WORLD);
    pt_cp.start();
    
    field_vector_deserialize(recv_buff,row_data);
    codeword = row_data;
    codeword.resize(codeword.size()*2,F(0));
    fft(codeword,(int)log2(codeword.size()),false);
    pt_cp.end();
    
    distributed_MT(codeword,Com,N);
}





quadratic_poly step1(int rnd, F b,vector<F> &beta, vector<F> &data, vector<F> &mask_data){
    // Perform the first step of sumcheck
    linear_poly l1,l2;
	quadratic_poly partial_poly = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
    if(mask_data.size() != 0){
        for(int i = 0; i < data.size()/(1ULL<<(rnd)); i++){
            data[i] += b*mask_data[i];
        }
    }
    

	for(int i = 0; i < data.size()/(1ULL<<(rnd+1)); i++){
        l1 = linear_poly(data[2*i+1] - data[2*i],data[2*i]);
		l2 = linear_poly(beta[2*i+1] - beta[2*i],beta[2*i]);
		partial_poly = partial_poly + l1*l2;
    }    
    return partial_poly;
}


void step2(F a, F b, int rnd, vector<F> &beta, vector<F> &data, vector<F> &codeword,vector<F> &masked_codeword, MT &Hashes, int N){
    // Fold+Commit the codeword and reduce data given the random point a
    if(b != F(0)){
        for(int i = 0; i < masked_codeword.size(); i++){
            codeword[i] += b*masked_codeword[i]; 
        }
    }
    
    RS_fold(codeword,a);
    merkle_tree::merkle_tree_prover::MT_commit_Blake(codeword.data(),Hashes.Base_MT, codeword.size());
    // Distributed MT is not needed her. It will be done in the next sumcheck round to save some synch rounds
    //distributed_MT(codeword,Hashes,N);
    for(int i = 0; i < data.size()/(1ULL<<(rnd+1)); i++){
        data[i] = data[2*i] + a*(data[2*i+1]-data[2*i]);
        beta[i] = beta[2*i] + a*(beta[2*i+1]-beta[2*i]);
    }
        
}


// Identical to query algorithm 
void verify_queries(int N,int M,vector<vector<u32>> query_indexes, 
                                 vector<vector<vector<F>>> replies,
                                 vector<vector<vector<F>>> replies_mask,
                                 vector<F> a,
                                 vector<F> b,
                                 MT &Initial_tree,
                                 vector<MT> &Middle_trees,
                                 double &ps,
                                 bool verify = true){
    
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    
    int row_size = 4*M;
    double temp_ps = 0.0;
    vector<vector<bool>> visited(N);
    for(int i = 0; i < visited.size(); i++){
        visited[i].resize(2*M,false);
    }
    vector<_hash> path;
    vt.start();
        
    for(int i = 0; i < query_indexes.size(); i++){
        path = merkle_tree::merkle_tree_prover::open_tree_blake(Initial_tree.Base_MT,query_indexes[i][1]/4);
        merkle_tree::merkle_tree_verifier::verify_claim_opt_blake(Initial_tree.Base_MT,path.data(),query_indexes[i][1]/4,M,visited[query_indexes[i][0]],temp_ps);
        ps += temp_ps;
        if(replies_mask.size() != 0){
            ps += temp_ps;
        }
        temp_ps = 0.0;
    }

    if(rank == 0) ps += 32.0*(int)(N)/1024.0;

    vector<vector<u32>> temp_queries = query_indexes;
    for(int i = 0; i < Middle_trees.size(); i++){
        for(int j = 0; j < temp_queries.size(); j++){
            if(temp_queries[j][1] >= 4*M/2){
                temp_queries[j][1] -= 4*M/2;
            }
        }
        M = M/2;
        for(int j = 0; j < visited.size(); j++){
            visited[j].resize(2*M,false);
        }
        for(int j = 0; j < temp_queries.size(); j++){
            path = merkle_tree::merkle_tree_prover::open_tree_blake(Middle_trees[i].Base_MT,temp_queries[j][1]/4);
            if(path.size() != 0){
                merkle_tree::merkle_tree_verifier::verify_claim_opt_blake(Middle_trees[i].Base_MT,path.data(),temp_queries[j][1]/4,M,visited[temp_queries[j][0]],temp_ps);
                if(replies_mask.size() > i){
                    ps += temp_ps;
                }
                ps += temp_ps;
                temp_ps = 0.0;
            }else{
                if(replies_mask.size() > i){
                    ps += 32.0/1024.0;
                }
                ps += 32.0/1024.0;
                temp_ps = 0.0;
            }
        }
        if(rank == 0) ps += 32.0*(int)(N)/1024.0;
    }
    F two_inv = F(2).inv();
    for(int i = 0; i < replies.size()-1; i++){
                
        F omega = getRootOfUnity((int)log2(row_size/(1<<i))).inv();
        vector<F> aggregation;
        for(int j = 0; j < query_indexes.size(); j++){
            F pow;
            if(query_indexes[j][1] < (row_size/(1<<(i+1)))){
                pow = pow.fastPow(omega,query_indexes[j][1]);
            }else{
                pow = pow.fastPow(omega,query_indexes[j][1]-(row_size/(1<<(i+1))));
            }
          
            F aggr1 = two_inv*((F(1)-a[i])*(replies[i][j][0]+replies[i][j][1]) + pow*a[i]*(replies[i][j][0]-replies[i][j][1]));
            F aggr2 = F(0);
           if(replies_mask.size() > i){
                aggr2 = two_inv*((F(1)-a[i])*(replies_mask[i][j][0]+replies_mask[i][j][1]) + pow*a[i]*(replies_mask[i][j][0]-replies_mask[i][j][1]));
            }
            
            if(query_indexes[j][1] >= (row_size/(1<<(i+1)))){
                query_indexes[j][1] -= (row_size/(1<<(i+1)));
            }
            if(replies_mask.size() > i){
                if(verify && (query_indexes[j][1] < (row_size/(1<<(i+2))) && (replies[i+1][j][0] != aggr1 + b[i]*aggr2))){
                    printf("# error %d\n",j);
                    //return;
                }
                if(verify && (query_indexes[j][1] > (row_size/(1<<(i+2))) && (replies[i+1][j][1] != aggr1 + b[i]*aggr2))){
                    printf("! error %d\n",j);
                    //return;
                }
            }else{
                if(verify && (query_indexes[j][1] < (row_size/(1<<(i+2))) && (replies[i+1][j][0] != aggr1 ))){
                    printf("@ error %d,%d\n",i,j);
                    //return;
                }
                if(verify && (query_indexes[j][1] > (row_size/(1<<(i+2))) && (replies[i+1][j][1] != aggr1 ))){
                    printf("> error %d,%d\n",i,j);
                    //return;
                }
            }
            

        }
    }
    vt.end();
        
    //printf("%lf\n",ps);

}


void verify_queries_local(int N,int M,vector<vector<u32>> query_indexes, 
                                 vector<vector<vector<F>>> replies,
                                 vector<F> a,
                                 vector<vector<MT>> &Middle_trees,
                                 double &ps,
                                 bool verify = true){
    
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    
    int row_size = 4*M;
    double temp_ps = 0.0;
    vector<_hash> path;
    vt.start();
    vector<vector<bool>> visited(N);
    vector<vector<u32>> temp_queries = query_indexes;
    for(int i = 0; i < Middle_trees.size(); i++){
        for(int j = 0; j < temp_queries.size(); j++){
            if(temp_queries[j][1] >= 4*M/2){
                temp_queries[j][1] -= 4*M/2;
            }
        }
        M = M/2;
        for(int j = 0; j < visited.size(); j++){
            visited[j].resize(2*M,false);
        }
        for(int j = 0; j < temp_queries.size(); j++){
            path = merkle_tree::merkle_tree_prover::open_tree_blake(Middle_trees[i][temp_queries[j][0]].Base_MT,temp_queries[j][1]/4);
            if(path.size() != 0){
                merkle_tree::merkle_tree_verifier::verify_claim_opt_blake(Middle_trees[i][temp_queries[j][0]].Base_MT,path.data(),temp_queries[j][1]/4,M,visited[temp_queries[j][0]],temp_ps);
                ps += temp_ps;
                temp_ps = 0.0;
            }else{
                ps += 32.0/1024.0;
                temp_ps = 0.0;
            }
        }
        ps += 32.0*(int)(N)/1024.0;
    }
    F two_inv = F(2).inv();
    
    for(int i = 0; i < replies.size()-1; i++){
                
        F omega = getRootOfUnity((int)log2(row_size/(1<<i))).inv();
        vector<F> aggregation;
        for(int j = 0; j < query_indexes.size(); j++){
            F pow;
            if(query_indexes[j][1] < (row_size/(1<<(i+1)))){
                pow = pow.fastPow(omega,query_indexes[j][1]);
            }else{
                pow = pow.fastPow(omega,query_indexes[j][1]-(row_size/(1<<(i+1))));
            }
          
            F aggr1 = two_inv*((F(1)-a[i])*(replies[i][j][0]+replies[i][j][1]) + pow*a[i]*(replies[i][j][0]-replies[i][j][1]));
            F aggr2 = F(0);
            
            if(query_indexes[j][1] >= (row_size/(1<<(i+1)))){
                query_indexes[j][1] -= (row_size/(1<<(i+1)));
            }
            if(verify && (query_indexes[j][1] < (row_size/(1<<(i+2))) && (replies[i+1][j][0] != aggr1 ))){
                printf("@ error %d,%d\n",i,j);
            }
            if(verify && (query_indexes[j][1] > (row_size/(1<<(i+2))) && (replies[i+1][j][1] != aggr1 ))){
                printf("> error %d,%d\n",i,j);
            }
            
        }
    }
    vt.end();
        
    //printf("%lf\n",ps);

}



void open_zk(vector<F> &codeword, vector<vector<F>> &mask_codeword, 
             vector<F> &row_data, vector<vector<F>> &mask_data, 
             MT &Com, vector<MT> Mask_Com, 
             vector<F> r, F y, int l, int k, int _k, int M, int N, double &ps, bool verify){
    
    
    pt_cp.start();
    
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    int rounds = (int)log2(row_data.size())-1;
    int masking_rounds = mask_codeword.size();
    vector<F> r1,r2,beta1,beta2;
    vector<vector<F>> folded_codewords(rounds);
    vector<MT> eval_MT(rounds);
    
    for(int i = 0; i < (int)log2(k); i++) r2.push_back(r[i]);
    
    for(int i = (int)log2(k); i < r.size(); i++) r1.push_back(r[i]);
    
    
    precompute_beta(r1,beta1);precompute_beta(r2,beta2);
    fft(row_data,(int)log2(row_data.size()),true);
    F omega = getRootOfUnity(1+(int)log2(rate)+(int)log2(row_data.size())).inv();
    F mul = F(1);
    for(int j = 0; j < row_data.size(); j++){
        row_data[j] = mul*row_data[j];
        mul = mul*omega;
    }
    fft(beta1,(int)log2(beta1.size()),false);
    omega = getRootOfUnity(1+(int)log2(rate)+(int)log2(row_data.size()));
    mul = F(1);
    for(int j = 0; j < row_data.size(); j++){
        beta1[j] = mul*beta1[j];
        mul = mul*omega;
    }

    
   vector<F> y_mask(rounds),aggr_challenges(rounds),challenges(rounds);
    
    quadratic_poly H;
    pt_cp.end();
    
    for(int i = 0; i < rounds; i++){

        folded_codewords[i] = codeword;
        if(i < masking_rounds){
            y_mask[i] = F_ip(mask_data[i],beta1,beta2,k,_k,N);
            aggr_challenges[i] = hash_to_field({y_mask[i]});
            //aggr_challenges[i] = F(0);
        }else{
            y_mask[i] = 0;
            aggr_challenges[i] = 0;
        }    
        pt_cp.start();
        
        if(i < masking_rounds){
            H = step1(i,aggr_challenges[i],beta1,row_data,mask_data[i]);
        }else{
            vector<F> dummy;
            H = step1(i,F(0),beta1,row_data,dummy);
        }
        pt_cp.end();
        
        H = aggregate_quadratic_poly(H, beta2,  k,  _k,  N);
        if(verify && H.eval(0) + H.eval(1) != y + aggr_challenges[i]*y_mask[i]){
            printf("> Error in open round %d\n",i);
            return;
        }
        pt_cp.start();
    
        challenges[i] = hash_to_field({H.a,H.b,H.c});
        y = H.eval(challenges[i]);
        
        if(i < masking_rounds){
            step2(challenges[i], aggr_challenges[i], i, beta1, row_data,codeword,mask_codeword[i],eval_MT[i],N);
        }else{
            vector<F> dummy;
            step2(challenges[i], aggr_challenges[i], i, beta1, row_data,codeword,dummy,eval_MT[i],N);
        }
        

        pt_cp.end();
    
    }
    // Generate opening proofs 
    vector<vector<u32>> initial_index, query_index = get_indexes(l,N,2*rate*(1<<rounds),rank);
    initial_index = query_index;
    vector<vector<vector<F>>> replies(rounds),replies_mask(masking_rounds); 
    for(int i = 0; i < rounds; i++){
        for(int j = 0; j < query_index.size(); j++){
            if(query_index[j][1] < folded_codewords[i].size()/2){
                replies[i].push_back({folded_codewords[i][query_index[j][1]],folded_codewords[i][query_index[j][1] + folded_codewords[i].size()/2]});
                
                if(i < masking_rounds){
                    replies_mask[i].push_back({mask_codeword[i][query_index[j][1]],mask_codeword[i][query_index[j][1] + mask_codeword[i].size()/2]});
                }
            }else{
                replies[i].push_back({folded_codewords[i][query_index[j][1]- folded_codewords[i].size()/2],folded_codewords[i][query_index[j][1]]});
                
                if(i < masking_rounds){
                    replies_mask[i].push_back({mask_codeword[i][query_index[j][1]- mask_codeword[i].size()/2],mask_codeword[i][query_index[j][1]]});
                }
            }
        }
        for(int j = 0; j < query_index.size(); j++){
            if(query_index[j][1] >= folded_codewords[i].size()/2){
                query_index[j][1] -= folded_codewords[i].size()/2;
            }
        }
    }
    
    verify_queries(N,folded_codewords[0].size()/4,  initial_index, replies, replies_mask,
                                 challenges, aggr_challenges, Com, eval_MT, ps);

    // Send the final codeword to P0
    com_rounds++;
    if(rank != 0){
        vector<u64> buff;
        field_vector_serialize(codeword,buff);
        cm += 8*buff.size()/1024.0;
        MPI_Send(buff.data(),buff.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD);
    }else{
        vt.start();
        
        vector<vector<F>> final_codeword(N);
        final_codeword[0] = codeword;
        vector<u64> buff(2*codeword.size());
        for(int i = 1; i < N; i++){
            MPI_Recv(buff.data(),buff.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            field_vector_deserialize(buff,codeword);
            final_codeword[i] = codeword;
        }
        ps += final_codeword.size()*final_codeword[0].size()*16/1024.0;
        vector<vector<F>> _final_codeword(N);
        for(int i = 0; i < N; i++){
            _final_codeword[i].resize(final_codeword[i].size()/rate,0);
            fft(final_codeword[i],(int)log2(final_codeword[i].size()),true);            
            for(int j = 0; j < _final_codeword[i].size(); j++){
                //printf("%d,%d\n",final_codeword[i].size(),2*rate*j );
                _final_codeword[i][j] = final_codeword[i][j ];
            }
        }
        
        F temp = 0;
        
        vector<vector<F>> message(_final_codeword[0].size());
        for(int i = 0; i < message.size(); i++){
            message[i].resize(N);
            for(int j = 0; j < message[i].size(); j++){
                message[i][j] = _final_codeword[j][i];
            }
            fft(message[i],(int)log2(N),true);
            
            F omega = getRootOfUnity(1+(int)log2(N)).inv();
            F mul = F(1);
            for(int j = 0; j < message[i].size(); j++){
                message[i][j] = mul*message[i][j];
                mul = mul*omega;
            }
            fft(message[i],(int)log2(N),false);
            vector<F> buff = message[i];
            message[i].resize(k);
            for(int j = 0; j < k; j++) message[i][j] = buff[N*j/_k];
        }
        for(int i = 0; i < k; i++){
            for(int j = 0; j < message.size(); j++){
                temp += beta2[i]*beta1[j]*message[j][i];
            }
        }
        if(temp != y){
            printf("ERROR\n");
        }else{
            //printf("PC Verification Success\n");
        }
        vt.end();
        
    }


}


void local_open(vector<vector<F>> &codeword, vector<vector<F>> &row_data, vector<F> &v1, vector<F> &v2,vector<F> &old_v2, vector<vector<u32>> &query_index,
                         F y, int l, int k, int N, double &ps, bool secret_shared, bool verify){
    
    pt_cp.start();
    int rounds = (int)log2(row_data[0].size())-1;
    vector<vector<vector<F>>> folded_codewords(rounds);
    vector<vector<MT>> eval_MT(rounds);
    vector<F> challenges(rounds);
    quadratic_poly H;
    for(int i = 0; i < rounds; i++){
        eval_MT[i].resize(N);
        for(int j = 0; j < codeword.size(); j++){
            folded_codewords[i].push_back(codeword[j]);
        }
        
        vector<F> dummy;
        vector<F> _a(N),_b(N),_c(N);
        H = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
        for(int j = 0; j < N; j++){
            quadratic_poly H_temp = step1(i,F(0),v1,row_data[j],dummy);
            if(!secret_shared){
                H_temp.a = v2[j]*H_temp.a;
                H_temp.b = v2[j]*H_temp.b;
                H_temp.c = v2[j]*H_temp.c;
                H = H + H_temp;
            }else{
                _a[j] = H_temp.a;_b[j] = H_temp.b;_c[j] = H_temp.c; 
            }
        }
        if(secret_shared){
            fft(_a,(int)log2(_a.size()),true);
            fft(_b,(int)log2(_a.size()),true);
            fft(_c,(int)log2(_a.size()),true);
            F omega = getRootOfUnity(1+(int)log2(N)).inv();
            F mul = F(1);
            for(int j = 0; j < _a.size(); j++){
                _a[j] = mul*_a[j];
                _b[j] = mul*_b[j];
                _c[j] = mul*_c[j];
                mul = mul*omega;
            }
            fft(_a,(int)log2(_a.size()),false);
            fft(_b,(int)log2(_a.size()),false);
            fft(_c,(int)log2(_a.size()),false);
            
            for(int j = 0; j < k; j++){
                H.a += v2[j]*_a[N*j/(2*k)];
                H.b += v2[j]*_b[N*j/(2*k)];
                H.c += v2[j]*_c[N*j/(2*k)];
            }
        }
        //printf("(%lld,%lld),(%lld,%lld),(%lld,%lld)\n",H.a.real,H.a.img,H.b.real,H.b.img,H.c.real,H.c.img);
        //H = aggregate_quadratic_poly(H, v2,  k,  _k,  N);
        if(H.eval(0) + H.eval(1) != y && verify){
            printf("Error in open round %d\n",i);
            //return;
        }
        challenges[i] = F::_random();
        y = H.eval(challenges[i]);
            
        for(int j = 0; j < N; j++){
            RS_fold(codeword[j],challenges[i]);
            merkle_tree::merkle_tree_prover::MT_commit_Blake(codeword[j].data(),eval_MT[i][j].Base_MT, codeword[j].size());
            for(int n = 0; n < row_data[j].size()/(1ULL<<(i+1)); n++){
                row_data[j][n] = row_data[j][2*n] + challenges[i]*(row_data[j][2*n+1]-row_data[j][2*n]);
            }
        }
        for(int j = 0; j < row_data[0].size()/(1ULL<<(i+1)); j++){
            v1[j] = v1[2*j] + challenges[i]*(v1[2*j+1]-v1[2*j]);
        }
    }
    pt_cp.end();
    
    vector<vector<u32>> initial_query_index = query_index;
    vector<vector<vector<F>>> replies(rounds); 
    for(int i = 0; i < rounds; i++){
        for(int j = 0; j < query_index.size(); j++){
            if(query_index[j][1] < folded_codewords[i][query_index[j][0]].size()/2){
                replies[i].push_back({folded_codewords[i][query_index[j][0]][query_index[j][1]],folded_codewords[i][query_index[j][0]][query_index[j][1] + folded_codewords[i][query_index[j][0]].size()/2]});
            }else{
                replies[i].push_back({folded_codewords[i][query_index[j][0]][query_index[j][1]- folded_codewords[i][query_index[j][0]].size()/2],folded_codewords[i][query_index[j][0]][query_index[j][1]]});
            }
            }
            for(int j = 0; j < query_index.size(); j++){
                if(query_index[j][1] >= folded_codewords[i][query_index[j][0]].size()/2){
                    query_index[j][1] -= folded_codewords[i][query_index[j][0]].size()/2;
                }
            }
        }

    verify_queries_local(N,folded_codewords[0][0].size()/4, initial_query_index, 
                                 replies,
                                 challenges,
                                 eval_MT,
                                 ps,
                                 verify);


        vt.start();
            vector<vector<F>> final_codeword = codeword;

            ps += final_codeword.size()*final_codeword[0].size()*16/1024.0;
            vector<vector<F>> _final_codeword(N);
            for(int i = 0; i < N; i++){
                
                _final_codeword[i].resize(final_codeword[i].size()/2,0);
                fft(final_codeword[i],(int)log2(final_codeword[i].size()),true);
                for(int j = 0; j < _final_codeword[i].size(); j++){
                    _final_codeword[i][j] = final_codeword[i][j];
                }
            }

            F temp = 0;
            
            vector<vector<F>> message(_final_codeword[0].size());
            for(int i = 0; i < message.size(); i++){
                message[i].resize(N);
                for(int j = 0; j < message[i].size(); j++){
                    message[i][j] = _final_codeword[j][i];
                }
                fft(message[i],(int)log2(N),true);
                if(!secret_shared){
                    message[i].resize(k);
                }else{
                    F omega = getRootOfUnity(1+(int)log2(N)).inv();
                    F mul = F(1);
                    for(int j = 0; j < message[i].size(); j++){
                        message[i][j] = mul*message[i][j];
                        mul = mul*omega;
                    }        
                    fft(message[i],(int)log2(N),false);
                    vector<F> buff = message[i];
                    message[i].clear();
                    for(int j = 0; j < k; j++){
                        message[i].push_back(buff[N*j/(2*k)]);
                    }                
                }
            }

            vector<F> arr1 = convert2vector((message)),arr2;
            for(int i = 0; i < v1.size()/(1ULL<<rounds); i++){
                for(int j = 0; j < old_v2.size(); j++){
                    arr2.push_back(old_v2[j]*v1[i]);
                }
            } 
            
            for(int i = 0; i < arr1.size(); i++) temp += arr1[i]*arr2[i];
            
            if(temp != y && verify){
                printf("ERROR, PC verification failed (%lld,%lld),(%lld,%lld)\n",temp.real,temp.img,y.real,y.img);
            }else{
                //printf("PC Verification Success\n");
            }
            vt.end();
            
        
}


void recv_batch_PC_data(vector<vector<vector<F>>> &codeword, vector<vector<vector<F>>> &row_data, vector<vector<vector<u32>>> &query_index, vector<int> codeword_size, vector<int> size, vector<int> l, int N){
    vector<vector<u64>> buff64(N-1);
    int batch_size = codeword_size.size();
    int codewords_len = 0, row_len = 0,l_len = 0;
    for(int i = 0; i < batch_size; i++){
        codewords_len += codeword_size[i];
        row_len += size[i];
        l_len += l[i];
    }
    for(int i = 0; i < N-1;i++) buff64[i].resize(2*(codewords_len+row_len)+l_len+batch_size); 
    
    codeword.clear();
    row_data.clear();
    codeword.resize(batch_size);
    row_data.resize(batch_size);
    for(int i = 0; i < codeword.size(); i++){
        codeword[i].resize(N);
        row_data[i].resize(N);
    }
    
    vector<vector<u64>> code_buff(batch_size),row_buff(batch_size);
    for(int i = 0; i < batch_size; i++){
        code_buff[i].resize(2*codeword_size[i]);
        row_buff[i].resize(2*size[i]);
    }
    vector<MPI_Request> stat(N-1);
    
    for(int i = 1; i < N; i++){
        MPI_Irecv(buff64[i-1].data(),buff64[i-1].size(),MPI_UINT64_T, i,0,MPI_COMM_WORLD,&stat[i-1]);
    }
    for(int i = 1; i < N; i++){
        MPI_Wait(&stat[i-1],MPI_STATUS_IGNORE);
        //field_vector_deserialize(buff64,buff);
        //codeword[i];
        //row_data[i];
        int ctr = 0;
        for(int h = 0; h < batch_size; h++){
            for(int j = 0; j < 2*codeword_size[h]; j++) code_buff[h][j] = buff64[i-1][ctr++];
            field_vector_deserialize(code_buff[h],codeword[h][i]);
        }
        for(int h = 0; h < batch_size; h++){
            for(int j = 0; j < 2*size[h]; j++) row_buff[h][j] = buff64[i-1][ctr++];
            
            field_vector_deserialize(row_buff[h],row_data[h][i]);
            
        }
        //for(int j = 0; j < 2*size; j++) {row_buff[j] = buff64[i-1][ctr++];}
        
        
        //field_vector_deserialize(row_buff,row_data[i]);
        for(int h = 0; h < batch_size; h++){
            int queries = buff64[i-1][ctr++];

            for(int j = 0; j < queries; j++) query_index[h].push_back({(u32)i,(u32)buff64[i-1][ctr++]});
            ctr +=( l[h] - queries);
        }
        
    }
}

void recv_PC_data(vector<vector<F>> &codeword, vector<vector<F>> &row_data, vector<vector<u32>> &query_index, int codeword_size, int size, int l, int N){
    vector<vector<u64>> buff64(N-1);
    for(int i = 0; i < N-1;i++) buff64[i].resize(2*(codeword_size+size)+l+1); 
    vector<u64> code_buff(2*codeword_size),row_buff(2*size);
    vector<MPI_Request> stat(N-1);
    for(int i = 1; i < N; i++){
        
        MPI_Irecv(buff64[i-1].data(),buff64[i-1].size(),MPI_UINT64_T, i,0,MPI_COMM_WORLD,&stat[i-1]);
    }
    for(int i = 1; i < N; i++){
        MPI_Wait(&stat[i-1],MPI_STATUS_IGNORE);
        //field_vector_deserialize(buff64,buff);
        //codeword[i];
        //row_data[i];
        int ctr = 0;
        for(int j = 0; j < 2*codeword_size; j++) code_buff[j] = buff64[i-1][ctr++];
        for(int j = 0; j < 2*size; j++) {row_buff[j] = buff64[i-1][ctr++];}
        
        
        field_vector_deserialize(code_buff,codeword[i]);
        field_vector_deserialize(row_buff,row_data[i]);
         
        int queries = buff64[i-1][ctr++];
        //printf("> %d\n",queries);
        for(int j = 0; j < queries; j++) query_index.push_back({(u32)i,(u32)buff64[i-1][ctr++]});
        
    }
}

void send_PC_data(vector<F> &codeword, vector<F> &row_data, int size, vector<vector<u32>> query_index, int l){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    MPI_Request stat;
    vector<F> data(size);
    for(int i = 0; i < data.size(); i++){
        data[i] = row_data[i];
    }
    if(rank != 0){
        vector<F> buff;
        vector<u64> buff_64;
        buff = codeword;
        buff.insert(buff.end(),data.begin(),data.end());
        int ctr = 2*buff.size();
        field_vector_serialize(buff,buff_64);
        buff_64.resize(buff_64.size()+l+1,0);
        buff_64[ctr++] = query_index.size();
        for(int i = 0; i < query_index.size(); i++){
            buff_64[ctr++] = query_index[i][1];
        }
        
        MPI_Isend(buff_64.data(),buff_64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&stat);
        MPI_Wait(&stat, MPI_STATUS_IGNORE);
    }
    
}

void send_batch_PC_data(vector<vector<F>> &codeword, vector<vector<F>> &row_data, vector<int> size, vector<vector<vector<u32>>> query_index, vector<int> l){
    int rank;
    int batch_size = codeword.size();
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    MPI_Request stat;
    vector<vector<F>> data(batch_size);
    for(int j = 0; j < batch_size; j++){
        data[j].resize(size[j]);
        for(int i = 0; i < size[j]; i++){
            data[j][i] = row_data[j][i];
        }
    }
    
    if(rank != 0){
        vector<F> buff;
        vector<u64> buff_64;
        buff = convert2vector(codeword);
        for(int i = 0; i < data.size(); i++){
            buff.insert(buff.end(),data[i].begin(),data[i].end());
        }
        int ctr = 2*buff.size();
        field_vector_serialize(buff,buff_64);
        int num_l = 0;
        for(int i = 0; i < l.size(); i++) num_l += l[i];
        buff_64.resize(buff_64.size()+batch_size + num_l,0);
        for(int j = 0; j < batch_size; j++){
            
            buff_64[ctr++] = query_index[j].size();
            for(int i = 0; i < query_index[j].size(); i++){
                buff_64[ctr++] = query_index[j][i][1];
            }    
            ctr+= (l[j]-query_index[j].size());
        }
        
        MPI_Isend(buff_64.data(),buff_64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&stat);
        MPI_Wait(&stat, MPI_STATUS_IGNORE);
    }
    
}


void open_plaintext(vector<F> &codeword, vector<F> &row_data,
                    vector<F> &v1, vector<F> &v2, MT &Com, F y, int l, int k, int N, double &ps, bool secret_shared, bool verify){

    pt_cp.start();
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<F> old_v2 = v2;
    if(!secret_shared && k != N){
        fft(v2,(int)log2(v2.size()),true);
        vector<F> _v2(2*v2.size(),F(0));
        
        for(int i = 0; i < k; i++){
            _v2[i*N/k] = v2[i];
        }
        v2 = _v2;
    }
    vector<vector<u32>> initial_index, query_index;
    
    
    int rounds = (int)log2(row_data.size())-1-PC_offset;
    pt_cp.end();
        
    if(rounds > 0){
        //if(rank == 0) printf("Rounds: %d, Size: %d\n",rounds,row_data.size()*N);
        vector<vector<F>> folded_codewords(rounds);
        vector<MT> eval_MT(rounds);
        vector<F> challenges(rounds);
        
        quadratic_poly H;
        
        for(int i = 0; i < rounds; i++){
            folded_codewords[i] = codeword;
            pt_cp.start();
            
            vector<F> dummy;
            H = step1(i,F(0),v1,row_data,dummy);
            
            //printf("(%lld,%lld),(%lld,%lld),(%lld,%lld)\n",H.a.real,H.a.img,H.b.real,H.b.img,H.c.real,H.c.img);
            pt_cp.end();
            if(!secret_shared){
                H.a = v2[rank]*H.a;
                H.b = v2[rank]*H.b;
                H.c = v2[rank]*H.c;
                H = aggregate_poly(H, N);
            }
            else H = aggregate_quadratic_poly(H,v2,k,2*k,N);
            //H = aggregate_quadratic_poly(H, v2,  k,  _k,  N);
            pt_cp.start();
            if(H.eval(0) + H.eval(1) != y && verify){
                printf("Error in open round %d\n",i);
                //return;
            }
            challenges[i] = hash_to_field({H.a,H.b,H.c});
            y = H.eval(challenges[i]);
            step2(challenges[i], F(0), i, v1, row_data,codeword,dummy,eval_MT[i],N);
            pt_cp.end();
        
        }


        query_index = get_indexes(l,N,2*2*(1<<rounds),rank);
        initial_index = query_index;
        vector<vector<vector<F>>> replies(rounds); 
        for(int i = 0; i < rounds; i++){
            for(int j = 0; j < query_index.size(); j++){
                if(query_index[j][1] < folded_codewords[i].size()/2){
                    replies[i].push_back({folded_codewords[i][query_index[j][1]],folded_codewords[i][query_index[j][1] + folded_codewords[i].size()/2]});
                }else{
                    replies[i].push_back({folded_codewords[i][query_index[j][1]- folded_codewords[i].size()/2],folded_codewords[i][query_index[j][1]]});
                }
            }
            for(int j = 0; j < query_index.size(); j++){
                if(query_index[j][1] >= folded_codewords[i].size()/2){
                    query_index[j][1] -= folded_codewords[i].size()/2;
                }
            }
        }
        
        verify_queries(N,folded_codewords[0].size()/4,  initial_index, replies, {},
                                    challenges, {}, Com, eval_MT, ps,verify);
    }else{
        //if(rank == 0) printf("NO ROUNDS, Size: %d\n",row_data.size()*N);

        rounds = 0;
    }
    
    // Send the final codeword to P0
    com_rounds++;
    if(PC_offset){
        if(rank != 0){
            send_PC_data(codeword,row_data,row_data.size()/(1<<(rounds)),query_index,l);
            
        } 
        else{
            vector<vector<F>> all_codewords(N),all_row_data(N);
            //vector<vector<u32>> all_queries;
            all_codewords[0] = codeword;
            all_row_data[0].resize(row_data.size()/(1<<(rounds)));
            for(int i = 0; i  < row_data.size()/(1<<(rounds)); i++) all_row_data[0][i] = row_data[i];
            recv_PC_data(all_codewords,all_row_data,query_index,codeword.size(),row_data.size()/(1<<(rounds)),l,N);
            
            //all_queries.insert(all_queries.begin(),query_index);
            local_open(all_codewords,all_row_data,v1,v2,old_v2,query_index,y,l,k,N,ps,secret_shared,verify);
        }
    }else{
        if(rank != 0){
            vector<u64> buff;
            field_vector_serialize(codeword,buff);
            cm += 8*buff.size()/1024.0;
            MPI_Send(buff.data(),buff.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD);
        }else{
            vt.start();
            vector<vector<F>> final_codeword(N);
            final_codeword[0] = codeword;
            vector<u64> buff(2*codeword.size());
            for(int i = 1; i < N; i++){
                MPI_Recv(buff.data(),buff.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
                field_vector_deserialize(buff,codeword);
                final_codeword[i] = codeword;
            }
            ps += final_codeword.size()*final_codeword[0].size()*16/1024.0;
            vector<vector<F>> _final_codeword(N);
            for(int i = 0; i < N; i++){
                
                _final_codeword[i].resize(final_codeword[i].size()/2,0);
                fft(final_codeword[i],(int)log2(final_codeword[i].size()),true);
                for(int j = 0; j < _final_codeword[i].size(); j++){
                    _final_codeword[i][j] = final_codeword[i][j];
                }
            }

            F temp = 0;
            
            vector<vector<F>> message(_final_codeword[0].size());
            for(int i = 0; i < message.size(); i++){
                message[i].resize(N);
                for(int j = 0; j < message[i].size(); j++){
                    message[i][j] = _final_codeword[j][i];
                }
                fft(message[i],(int)log2(N),true);
                if(!secret_shared){
                    message[i].resize(k);
                }else{
                    F omega = getRootOfUnity(1+(int)log2(N)).inv();
                    F mul = F(1);
                    for(int j = 0; j < message[i].size(); j++){
                        message[i][j] = mul*message[i][j];
                        mul = mul*omega;
                    }        
                    fft(message[i],(int)log2(N),false);
                    vector<F> buff = message[i];
                    message[i].clear();
                    for(int j = 0; j < k; j++){
                        message[i].push_back(buff[N*j/(2*k)]);
                    }                
                }
            }

            vector<F> arr1 = convert2vector((message)),arr2;
            for(int i = 0; i < v1.size()/(1ULL<<rounds); i++){
                for(int j = 0; j < old_v2.size(); j++){
                    arr2.push_back(old_v2[j]*v1[i]);
                }
            } 
            
            for(int i = 0; i < arr1.size(); i++) temp += arr1[i]*arr2[i];
            
            if(temp != y && verify){
                printf("ERROR, PC verification failed (%lld,%lld),(%lld,%lld)\n",temp.real,temp.img,y.real,y.img);
            }else{
                //printf("PC Verification Success\n");
            }
            vt.end();
            
            
        }
    }
    
    
}


void batch_open(vector<vector<F>> &codeword, vector<vector<F>> &row_data,
                    vector<vector<F>> &v1, vector<vector<F>> &v2, vector<MT> &Com, vector<F> y, vector<int> l, vector<int> k, int N, double &ps, vector<bool> secret_shared, vector<bool> verify){
    
    pt_cp.start();
    int batch_size = codeword.size();
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    
    vector<vector<F>> old_v2 = v2;
    for(int i = 0; i < codeword.size(); i++){
        if(!secret_shared[i] && k[i] != N){
            fft(v2[i],(int)log2(v2[i].size()),true);
            vector<F> _v2(2*v2[i].size(),F(0));
            
            for(int j = 0; j < k[i]; j++){
                _v2[j*N/k[i]] = v2[i][j];
            }
            v2[i] = _v2;
        }
    
    }
    
    vector<vector<vector<u32>>> initial_index(batch_size), query_index(batch_size);
    
    vector<int> rounds;
    for(int i = 0; i < row_data.size(); i++){
        rounds.push_back((int)log2(row_data[i].size())-1-PC_offset);
    }
    pt_cp.end();
    
    vector<vector<vector<F>>> folded_codewords(rounds.size());
    vector<vector<MT>> eval_MT(rounds.size());
    int max_rounds = 0;
    for(int i = 0; i < folded_codewords.size(); i++){
        if(rounds[i] > 0){
            folded_codewords[i].resize(rounds[i]);
            eval_MT[i].resize(rounds[i]);
        }else{
            rounds[i] = 0;
            folded_codewords[i].resize(1);
            folded_codewords[i][0] = codeword[i];
        }
        if(rounds[i] > max_rounds){
            max_rounds = rounds[i];
        }

    }
    vector<F> challenges(max_rounds);
        
    vector<quadratic_poly> H(rounds.size());
    
    
    
    for(int i = 0; i < max_rounds; i++){
        vector<F> dummy;
        for(int j = 0; j < batch_size; j++){
            if(rounds[j] > i) folded_codewords[j][i] = codeword[j]; 
            pt_cp.start();            
            if(rounds[j] > i) H[j] = step1(i,F(0),v1[j],row_data[j],dummy);
            //printf("(%lld,%lld),(%lld,%lld),(%lld,%lld)\n",H.a.real,H.a.img,H.b.real,H.b.img,H.c.real,H.c.img);
            pt_cp.end();
        
        }
        H = batch_aggregate(H, v2, secret_shared, rounds,k, i, N);
        //printf("%d (%lld,%lld),(%lld,%lld),(%lld,%lld)\n",i,H[1].a.real,H[1].a.img,H[1].b.real,H[1].b.img,H[1].c.real,H[1].c.img);
        pt_cp.start();
        for(int j = 0; j < batch_size; j++){
            if(rounds[j] > i){
                if(H[j].eval(0) + H[j].eval(1) != y[j] && verify[j]){
                    printf("Error in open round %d,%d, (%lld,%lld)\n",i,rank,(H[j].eval(0) + H[j].eval(1)).real,(H[j].eval(0) + H[j].eval(1)).img);
                    //exit(-1);
                }
                //if(rank == 1 && verify[j]) printf("%d (%lld,%lld)\n",i,(H[j].eval(0) + H[j].eval(1)).real,(H[j].eval(0) + H[j].eval(1)).img);

            }
            
        }
        
        challenges[i] = hash_to_field({});
        for(int j = 0; j < batch_size; j++){
            if(rounds[j] > i) y[j] = H[j].eval(challenges[i]);    
        }
        
        for(int j = 0; j < batch_size; j++){
            if(rounds[j] > i) step2(challenges[i], F(0), i, v1[j], row_data[j],codeword[j],dummy,eval_MT[j][i],N);
        }        
        
        pt_cp.end();
        
    }
    
    for(int i = 0;  i < batch_size; i++){
        query_index[i] = get_indexes(l[i],N,folded_codewords[i].size(),rank);    
        initial_index[i] = query_index[i];   
    }
    vector<vector<vector<vector<F>>>> replies(batch_size);
    for(int i = 0; i < replies.size(); i++){
        replies[i].resize(rounds[i]);
    } 
    for(int h = 0; h < batch_size; h++){
        for(int i = 0; i < rounds[h]; i++){
            for(int j = 0; j < query_index[h].size(); j++){
                if(query_index[h][j][1] < folded_codewords[h][i].size()/2){
                    replies[h][i].push_back({folded_codewords[h][i][query_index[h][j][1]],folded_codewords[h][i][query_index[h][j][1] + folded_codewords[h][i].size()/2]});
                }else{
                    replies[h][i].push_back({folded_codewords[h][i][query_index[h][j][1]- folded_codewords[h][i].size()/2],folded_codewords[h][i][query_index[h][j][1]]});
                }
            }
            for(int j = 0; j < query_index[h].size(); j++){
                if(query_index[h][j][1] >= folded_codewords[h][i].size()/2){
                    query_index[h][j][1] -= folded_codewords[h][i].size()/2;
                }
            }
        }
        if(rounds[h]) verify_queries(N,folded_codewords[h][0].size()/4,  initial_index[h], replies[h], {},
                                    challenges, {}, Com[h], eval_MT[h], ps,verify[h]);
   
    }
    if(PC_offset){
        vector<int> row_data_size(batch_size),codeword_size(batch_size);
        
        for(int i = 0; i < batch_size; i++){
            if(rounds[i] > 0){
                row_data_size[i] = row_data[i].size()/(1<<(rounds[i]));                            
            }else{
                row_data_size[i] = row_data[i].size();
            }
            codeword_size[i] = codeword[i].size();
        } 

        if(rank != 0){
            send_batch_PC_data(codeword,row_data,row_data_size,query_index,l);  
        } 
        else{
            vector<vector<vector<F>>> all_codewords,all_row_data;
            //vector<vector<u32>> all_queries;
            //all_codewords[0] = codeword;
            //all_row_data[0].resize(row_data.size()/(1<<(rounds)));
            recv_batch_PC_data(all_codewords,all_row_data,query_index,codeword_size,row_data_size,l,N);
            for(int i = 0; i < batch_size; i++){
                all_codewords[i][0] = codeword[i];
                all_row_data[i][0].resize(row_data_size[i]);
                for(int j = 0; j  < row_data_size[i]; j++){
                    all_row_data[i][0][j] = row_data[i][j];
            
                }
            }
            //all_queries.insert(all_queries.begin(),query_index);
            for(int i = 0; i < batch_size; i++){ 
                local_open(all_codewords[i],all_row_data[i],v1[i],v2[i],old_v2[i],query_index[i],y[i],l[i],k[i],N,ps,secret_shared[i],verify[i]);
            }
        }
        //open_plaintext(codeword[0],row_data[0],v1[0],v2[0],Com[0],y[0],l[0],k[0],N,ps,secret_shared[0],verify[0]);
           
    }    
 
}

//void open_index(vector<F> &row_data, vector<F> &codeword, MT &index_Com, int rate){
//    int 
//}