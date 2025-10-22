#include "coPCS.h"
#include "Fiat_Shamir.h"
#include "Distributed_Sumcheck.h"
extern int rate;

void distributed_MT(vector<F> &data, MT &Com, int N){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    merkle_tree::merkle_tree_prover::MT_commit_Blake(data.data(),Com.Base_MT, data.size());
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
            MPI_Send(buff.data(),buff.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        }
    }else{
        buff.resize(2*l);
        MPI_Recv(buff.data(),2*l,MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        field_vector_deserialize(buff,R_shares);
    }


    if((int)log2(M/k)-1 <= (int)log2(next_pow2(l))){
        mask_shares.resize(1);
        if(rank == 0){
            vector<vector<vector<F>>> all_mask_shares(1);
            setup(all_mask_shares[0],N,M,3*l+M/k,k,_k);
            all_mask_shares[0] = transpose(all_mask_shares[0]);
            mask_shares[0] = all_mask_shares[0][0];
            for(int i = 1; i < N; i++){
                field_vector_serialize(all_mask_shares[0][i],buff);            
                MPI_Send(buff.data(),buff.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD);
            }
        }else{
            buff.clear();buff.resize(2*(3*l + M/k));
            MPI_Recv(buff.data(),2*(3*l + M/k),MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
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
            C_mask[i].resize(next_pow2(M/k+3*l)/(1<<i),F(0));
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
    printf("Shares Dim : %d,%d\n",shares.size(),shares[0].size());
    vector<F> shares_v = convert2vector(shares);
    vector<u64> send_buff,recv_buff;
    
    field_vector_serialize(shares_v,send_buff);
    recv_buff.resize(send_buff.size());

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
    distributed_MT(codeword, Com,N);
}


void plaintext_commit(vector<F> &data, vector<F> &codeword ,vector<F> &row_data, MT &Com, int k, int N){
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

    MPI_Alltoall(send_buff.data(),send_buff.size()/N,MPI_UINT64_T,recv_buff.data(),recv_buff.size()/N,MPI_UINT64_T,MPI_COMM_WORLD);

    field_vector_deserialize(recv_buff,row_data);
    codeword = row_data;
    codeword.resize(codeword.size()*2,F(0));
    fft(codeword,(int)log2(codeword.size()),false);
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
    distributed_MT(codeword,Hashes,N);
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
                                 double &ps){
    
    int row_size = 4*M;
    double temp_ps = 0.0;
    vector<vector<bool>> visited(N);
    for(int i = 0; i < visited.size(); i++){
        visited[i].resize(2*M,false);
    }
    vector<_hash> path;
    for(int i = 0; i < query_indexes.size(); i++){
        path = merkle_tree::merkle_tree_prover::open_tree_blake(Initial_tree.Base_MT,query_indexes[i][1]/4);
        merkle_tree::merkle_tree_verifier::verify_claim_opt_blake(Initial_tree.Base_MT,path.data(),query_indexes[i][1]/4,M,visited[query_indexes[i][0]],temp_ps);
        ps += temp_ps;
        if(replies_mask.size() != 0){
            ps += temp_ps;
        }
        temp_ps = 0.0;
    }
    if(ps > 0){
        ps += 32.0*(int)log2(N)/1024.0;
    }
    
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
            merkle_tree::merkle_tree_verifier::verify_claim_opt_blake(Middle_trees[i].Base_MT,path.data(),temp_queries[j][1]/4,M,visited[temp_queries[j][0]],temp_ps);
            if(replies_mask.size() > i){
                ps += temp_ps;
            }
            ps += temp_ps;
            temp_ps = 0.0;
        }
        if(ps > 0){
            ps += 32.0*(int)log2(N)/1024.0;
        }
    
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
                if(query_indexes[j][1] < (row_size/(1<<(i+2))) && (replies[i+1][j][0] != aggr1 + b[i]*aggr2)){
                    printf("# error %d\n",j);
                    //return;
                }
                if(query_indexes[j][1] > (row_size/(1<<(i+2))) && (replies[i+1][j][1] != aggr1 + b[i]*aggr2)){
                    printf("! error %d\n",j);
                    //return;
                }
            }else{
                if(query_indexes[j][1] < (row_size/(1<<(i+2))) && (replies[i+1][j][0] != aggr1 )){
                    printf("@ error %d,%d\n",i,j);
                    //return;
                }
                if(query_indexes[j][1] > (row_size/(1<<(i+2))) && (replies[i+1][j][1] != aggr1 )){
                    printf("> error %d,%d\n",i,j);
                    //return;
                }
            }
            

        }
    }
    //printf("%lf\n",ps);

}



void open_zk(vector<F> &codeword, vector<vector<F>> &mask_codeword, 
             vector<F> &row_data, vector<vector<F>> &mask_data, 
             MT &Com, vector<MT> Mask_Com, 
             vector<F> r, F y, int l, int k, int _k, int M, int N, double &ps, double &vt){
    
    
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
    fft(beta1,(int)log2(beta1.size()),false);
    

    vector<F> y_mask(rounds),aggr_challenges(rounds),challenges(rounds);
    
    quadratic_poly H;
   
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
        if(i < masking_rounds){
            H = step1(i,aggr_challenges[i],beta1,row_data,mask_data[i]);
        }else{
            vector<F> dummy;
            H = step1(i,F(0),beta1,row_data,dummy);
        }
        H = aggregate_quadratic_poly(H, beta2,  k,  _k,  N);
        if(H.eval(0) + H.eval(1) != y + aggr_challenges[i]*y_mask[i]){
            printf("Error in open round %d\n",i);
            return;
        }
        challenges[i] = hash_to_field({H.a,H.b,H.c});
        y = H.eval(challenges[i]);

        if(i < masking_rounds){
            step2(challenges[i], aggr_challenges[i], i, beta1, row_data,codeword,mask_codeword[i],eval_MT[i],N);
        }else{
            vector<F> dummy;
            step2(challenges[i], aggr_challenges[i], i, beta1, row_data,codeword,dummy,eval_MT[i],N);
        }
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
    if(rank != 0){
        vector<u64> buff;
        field_vector_serialize(codeword,buff);
        MPI_Send(buff.data(),buff.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD);
    }else{
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
            message[i].resize(_k);
            fft(message[i],(int)log2(_k),false);
        }
        for(int i = 0; i < _k; i++){
            for(int j = 0; j < message.size(); j++){
                temp += beta2[i]*beta1[j]*message[j][i];
            }
        }
        if(temp != y){
            printf("ERROR\n");
        }else{
            printf("PC Verification Success\n");
        }
        
    }


}

void open_plaintext(vector<F> &codeword, vector<F> &row_data,
                    vector<F> &v1, vector<F> &v2, MT &Com, F y, int l, int k, int N, double &ps, double &vt, bool secret_shared, bool verify){

    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    int rounds = (int)log2(row_data.size())-1;
    
    vector<vector<F>> folded_codewords(rounds);
    vector<MT> eval_MT(rounds);
    vector<F> old_v2 = v2;
    if(!secret_shared && k != N){
        fft(v2,(int)log2(v2.size()),true);
        vector<F> _v2(2*v2.size(),F(0));
        
        for(int i = 0; i < k; i++){
            _v2[i*N/k] = v2[i];
        }
        v2 = _v2;
    }
    
    vector<F> challenges(rounds);
    
    quadratic_poly H;
    for(int i = 0; i < rounds; i++){
        folded_codewords[i] = codeword;
            
        vector<F> dummy;
        H = step1(i,F(0),v1,row_data,dummy);
        
        //printf("(%lld,%lld),(%lld,%lld),(%lld,%lld)\n",H.a.real,H.a.img,H.b.real,H.b.img,H.c.real,H.c.img);
        if(!secret_shared){
            H.a = v2[rank]*H.a;
            H.b = v2[rank]*H.b;
            H.c = v2[rank]*H.c;
            H = aggregate_poly(H, N);
        }
        else H = aggregate_quadratic_poly(H,v2,k,2*k,N);
        //H = aggregate_quadratic_poly(H, v2,  k,  _k,  N);
        if(H.eval(0) + H.eval(1) != y && verify){
            printf("Error in open round %d\n",i);
            //return;
        }
        challenges[i] = hash_to_field({H.a,H.b,H.c});
        y = H.eval(challenges[i]);
        step2(challenges[i], F(0), i, v1, row_data,codeword,dummy,eval_MT[i],N);
    }
    // Send the final codeword to P0
    if(rank != 0){
        vector<u64> buff;
        field_vector_serialize(codeword,buff);
        MPI_Send(buff.data(),buff.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD);
    }else{
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
            printf("PC Verification Success\n");
        }
        
    }
}

//void open_index(vector<F> &row_data, vector<F> &codeword, MT &index_Com, int rate){
//    int 
//}