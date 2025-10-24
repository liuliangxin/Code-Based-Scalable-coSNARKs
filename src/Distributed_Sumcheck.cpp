#include "MPI_utils.hpp"
#include "Distributed_Sumcheck.h"
#include "timer.hpp"
#include <unordered_map>
#include <algorithm>
extern timer pt_cp,vt;
double ps_plain = 0.0; 
extern double cm; 
vector<vector<pair<int, int>>> pA,pB,pC;
extern vector<int> real_idx_dim;

quadratic_poly aggregate_poly(quadratic_poly H, int N){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<F> buff; 
    vector<u64> buff_u64(6);
    if(rank == 0){
        for(int i = 1; i < N; i++){
            MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            field_vector_deserialize(buff_u64,buff);
            H = H + quadratic_poly(buff[0],buff[1],buff[2]);
        }
        buff = {H.a,H.b,H.c};
        field_vector_serialize(buff,buff_u64);
    }else{
        buff = {H.a,H.b,H.c};
        field_vector_serialize(buff,buff_u64);
        cm += 8*buff_u64.size()/1024.0;
        MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD);
    }   
    if(rank == 0)cm += (N-1)*8*buff_u64.size()/1024.0;
    MPI_Bcast(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,MPI_COMM_WORLD);
    if(rank != 0){
        field_vector_deserialize(buff_u64,buff);
        H = quadratic_poly(buff[0],buff[1],buff[2]);
    }
    return H;
}


cubic_poly aggregate_poly(cubic_poly H, int N, vector<F> &v){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<F> buff; 
    vector<u64> buff_u64(8);
    if(rank == 0){
        H.a  = v[0]*H.a;
        H.b  = v[0]*H.b;
        H.c  = v[0]*H.c;
        H.d  = v[0]*H.d;
        
        for(int i = 1; i < N; i++){
            MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            field_vector_deserialize(buff_u64,buff);
            H = H + cubic_poly(v[i]*buff[0],v[i]*buff[1],v[i]*buff[2],v[i]*buff[3]);
        }
        buff = {H.a,H.b,H.c,H.d};
        field_vector_serialize(buff,buff_u64);
    }else{
        buff = {H.a,H.b,H.c,H.d};
        field_vector_serialize(buff,buff_u64);
        cm += 8*buff_u64.size()/1024.0;
        MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD);
    }
    if(rank == 0) cm += (N-1)*8*buff_u64.size()/1024.0;
    MPI_Bcast(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,MPI_COMM_WORLD);
    if(rank != 0){
        field_vector_deserialize(buff_u64,buff);
        H = cubic_poly(buff[0],buff[1],buff[2],buff[3]);
    }
    return H;
}


vector<pair<F,vector<F>>> _quadratic_sumcheck(F y, vector<F> &v1, vector<F> &v2, int N){
	int offset = 4;
    //vector<F> r = generate_randomness(int(log2(v1.size())));
	int rounds = int(log2(v1.size()))-offset;
	int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    
    F rand;
	vector<F> r;
    if(rounds > 0){
        for(int i = 0; i < rounds; i++){
            pt_cp.start();
    
            quadratic_poly poly = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
            linear_poly l1,l2;
                
            int L = 1 << ((int)log2(v1.size()) -1- i);
            for(int j = 0; j < L; j++){
                l1 = linear_poly(v1[2*j+1] - v1[2*j],v1[2*j]);
                l2 = linear_poly(v2[2*j+1] - v2[2*j],v2[2*j]);
                poly = poly + (l1*l2);
            }

            vector<F> input;
            pt_cp.end();

            poly = aggregate_poly(poly,N);
            pt_cp.start();
            if(rank == 0)vt.start();
            
            if(poly.eval(0)+ poly.eval(1) != y){
                printf("Error in distributed sumcheck round %d\n",i);
                exit(-1);
            }
            rand = hash_to_field({poly.a,poly.b,poly.c});
            if(rank == 0)ps_plain += 16*(3)/1024.0;
        
            y = poly.eval(rand);
            if(rank == 0)vt.end();
        
            r.push_back(rand);        
            for(int j = 0; j < L; j++){
                v1[j] = rand*(v1[2*j+1]-v1[2*j]) + v1[2*j];
                v2[j] = rand*(v2[2*j+1]-v2[2*j]) + v2[2*j];
            }
            pt_cp.end();
    
        }
    }else{
        offset = int(log2(v1.size()));
    }
	
    vector<F> final_v1(1<<(offset)),final_v2(1<<(offset)),buff;
    vector<u64> buff_u64;
    for(int i = 0; i  <final_v1.size(); i++){
        final_v1[i] = v1[i];
        final_v2[i] = v2[i];
    }

    vector<F> reply;
    if(rank == 0){
        int idx = final_v1.size(); 
        buff_u64.resize(4*final_v1.size());    
        final_v1.resize(final_v1.size()*N,F(0));
        final_v2.resize(final_v2.size()*N,F(0));
        
        for(int i = 1; i < N; i++){
            MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            field_vector_deserialize(buff_u64,buff);
            for(int j = 0; j < (1<<offset); j++){
                final_v1[idx] = buff[j];
                final_v2[idx] = buff[j+ (buff.size()/2)];
                idx++;
            }   
        }
        pt_cp.start();
        
        vector<pair<F,vector<F>>> res = quadratic_sumcheck(y,final_v1,final_v2,F(0));
        if(rank == 0)ps_plain += 16*(2+3*(int)log2(N))/1024.0;
        
        reply.push_back(res[0].first);
        reply.push_back(res[1].first);
        reply.insert(reply.end(),res[0].second.begin(),res[0].second.end());
        field_vector_serialize(reply,buff_u64);
        pt_cp.end();
    
    }else{
        buff = final_v1; buff.insert(buff.end(),final_v2.begin(),final_v2.end());
        field_vector_serialize(buff,buff_u64);
        cm += 8*buff_u64.size()/1024.0;
        MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD);
        buff_u64.clear();buff_u64.resize(2*(2+offset+(int)log2(N))); 
    }
    if(rank == 0) cm += (N-1)*8*buff_u64.size()/1024.0;
    MPI_Bcast(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,MPI_COMM_WORLD);
	if(rank != 0){
        field_vector_deserialize(buff_u64,reply);
    }
    for(int i = 2; i < reply.size(); i++){
        r.push_back(reply[i]);
    }
  
    return {make_pair(reply[0] ,r),make_pair(reply[1] ,r)};
}



vector<pair<F,vector<F>>> _cubic_sumcheck(F y, vector<F> &v1, vector<F> &v2, vector<F> &v3, vector<F> &v, int N){
	int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    
    int offset = 4;
    //vector<F> r = generate_randomness(int(log2(v1.size())));
	int rounds = int(log2(v1.size()))-offset;
	F rand;
	vector<F> r;
	if(rounds > 0){
        for(int i = 0; i < rounds; i++){
            pt_cp.start();
    
            cubic_poly poly = cubic_poly(F_ZERO,F_ZERO,F_ZERO,F_ZERO);
            linear_poly l1,l2,l3;
                
            int L = 1 << ((int)log2(v1.size()) -1- i);
            for(int j = 0; j < L; j++){
                l1 = linear_poly(v1[2*j+1] - v1[2*j],v1[2*j]);
                l2 = linear_poly(v2[2*j+1] - v2[2*j],v2[2*j]);
                l3 = linear_poly(v3[2*j+1] - v3[2*j],v3[2*j]);
                poly = poly + (l1*l2*l3);
            }

            vector<F> input;
            pt_cp.end();
    
            poly = aggregate_poly(poly,N,v);
            pt_cp.start();
        
            if(rank == 0)vt.start();
        
            if(poly.eval(0)+ poly.eval(1) != y){
                printf("Error in distributed sumcheck round %d\n",i);
                exit(-1);
            }
            rand = hash_to_field({poly.a,poly.b,poly.c,poly.d});
            if(rank == 0)ps_plain += 16*4/1024.0;
            y = poly.eval(rand);
            if(rank == 0)vt.end();
            r.push_back(rand);        
            for(int j = 0; j < L; j++){
                v1[j] = rand*(v1[2*j+1]-v1[2*j]) + v1[2*j];
                v2[j] = rand*(v2[2*j+1]-v2[2*j]) + v2[2*j];
                v3[j] = rand*(v3[2*j+1]-v3[2*j]) + v3[2*j];
            }
            pt_cp.end();
    
        }    
    }else{
        offset = int(log2(v1.size()));
    }
    
    vector<F> final_v1(1<<(offset)),final_v2(1<<(offset)),final_v3(1<<(offset)),buff;
    vector<u64> buff_u64;
    for(int i = 0; i  <final_v1.size(); i++){
        final_v1[i] = v1[i];
        final_v2[i] = v2[i];
        final_v3[i] = v[rank]*v3[i];
    }
    
    vector<F> reply;
    if(rank == 0){
        int idx = final_v1.size(); 
        buff_u64.resize(6*final_v1.size());    
        final_v1.resize(final_v1.size()*N,F(0));
        final_v2.resize(final_v2.size()*N,F(0));
        final_v3.resize(final_v3.size()*N,F(0));
        
        for(int i = 1; i < N; i++){
            MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            field_vector_deserialize(buff_u64,buff);
            for(int j = 0; j < (1<<offset); j++){
                final_v1[idx] = buff[j];
                final_v2[idx] = buff[j+ (buff.size()/3)];
                final_v3[idx] = buff[j+ 2*(buff.size()/3)];
                idx++;
            }   
        }
        pt_cp.start();
    
        vector<pair<F,vector<F>>> res = cubic_sumcheck(y,final_v1,final_v2,final_v3,F(0));
        ps_plain += 16*(3+4*(int)log2(N))/1024.0;
            
        reply.push_back(res[0].first);
        reply.push_back(res[1].first);
        reply.push_back(res[2].first);
        reply.insert(reply.end(),res[0].second.begin(),res[0].second.end());
        field_vector_serialize(reply,buff_u64);
        pt_cp.end();
    
    }else{
        buff = final_v1; 
        buff.insert(buff.end(),final_v2.begin(),final_v2.end());
        buff.insert(buff.end(),final_v3.begin(),final_v3.end());
        field_vector_serialize(buff,buff_u64);
        cm += 8*buff_u64.size()/1024.0;
        MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD);
        buff_u64.clear();buff_u64.resize(2*(3+offset+(int)log2(N))); 
    
    }
    if(rank == 0) cm += (N-1)*8*buff_u64.size()/1024.0;
    MPI_Bcast(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,MPI_COMM_WORLD);
	if(rank != 0){
        field_vector_deserialize(buff_u64,reply);
    }
    for(int i = 3; i < reply.size(); i++){
        r.push_back(reply[i]);
    }
    return {make_pair(reply[0] ,r),make_pair(reply[1] ,r),make_pair(reply[2] ,r)};
}



pair<F,vector<vector<F>>> prove_product(vector<vector<F>> &input, vector<F> &output, F y, vector<F> r, int N){

    pt_cp.start();
    
    int vectors = input.size();
	int depth = (int)log2(next_pow2(input[0].size()));
	int size = input[0].size();
	for(int i = 0; i < input.size(); i++){
		if(input[i].size() != size){
			printf("Error in mul tree sumcheck, no equal size vectors %d,%d\n",input[i].size(),size);
			exit(-1);
		}
        input[i].resize(1<<depth,F(1));
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

    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    // Send outputs to the leader
    vector<u64> buff;
    pair<F,vector<F>> eval_claim;
    vector<F> buff_reply;
    pt_cp.end();
    if(rank == 0){
        vector<vector<F>> local_input(transcript[depth-1].size());
        for(int i = 0; i < local_input.size(); i++){
            local_input[i].resize(N);
            local_input[i][0] = transcript[depth-1][i];
        }
        buff.resize(2*transcript[depth-1].size());
        for(int i = 1; i < N; i++){
            MPI_Recv(buff.data(),buff.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            for(int j = 0; j < buff.size()/2; j++){
                local_input[j][i].real = buff[2*j];
                local_input[j][i].img = buff[2*j+1];
            }
        }
        pt_cp.start();
        eval_claim = prove_multiplication_tree_new(local_input, output, F(0),y, {});
        buff_reply.push_back(eval_claim.first);
        buff_reply.insert(buff_reply.end(),eval_claim.second.begin(),eval_claim.second.end());
        
        field_vector_serialize(buff_reply,buff);   
        pt_cp.end();
                
    }else{
    
        field_vector_serialize(transcript[depth-1],buff);
        cm += 8*buff.size()/1024.0;
        MPI_Send(buff.data(),buff.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD);
        buff.clear();buff.resize(2*(1 + log2(N*transcript[depth-1].size())));
    }
    if(rank == 0) cm += (N-1)*8*buff.size()/1024.0;
    //printf("%d ?? %d\n",rank,buff.size());
    
    MPI_Bcast(buff.data(),buff.size(),MPI_UINT64_T,0,MPI_COMM_WORLD);
    if(rank != 0){
        field_vector_deserialize(buff,buff_reply);
        eval_claim.first = buff_reply[0];
        for(int i = 1; i < buff_reply.size(); i++){
            eval_claim.second.push_back(buff_reply[i]);
        }
    }
    
    //printf("Final prod len : %d\n",transcript[depth-1].size());
		
	F sum = eval_claim.first;//evaluate_vector(transcript[depth-1],r);
    r = eval_claim.second;
    vector<F> r1,r2;
    for(int i = 0; i < (int)log2(N); i++){
        r1.push_back(r[i]);
    }
    for(int  i = r1.size(); i < r.size(); i++){
        r2.push_back(r[i]);
    }
    for(int i = depth-1; i >= 0; i--){
        pt_cp.start();
    
    	vector<F>  beta1,beta2;
		precompute_beta(r2,beta2);
        precompute_beta(r1,beta1);
        pt_cp.end();
    
        vector<pair<F,vector<F>>> claims = _cubic_sumcheck(sum,in1[i], in2[i],beta2, beta1, N );	
        
        pt_cp.start();
    
        F new_rand = hash_to_field(claims[0].second);
        r = claims[0].second;
        r.insert(r.begin(),new_rand);
        sum = (F(1)-new_rand)*claims[0].first + new_rand*claims[1].first;
        r1.clear();r2.clear();
        for(int j = 0; j < r.size()-(int)log2(N); j++){
            r2.push_back(r[j]);
        }
        for(int j = r2.size(); j  < r.size(); j++){
            r1.push_back(r[j]);
        }
        pt_cp.end();
    
	}
    pt_cp.start();
    

    vector<vector<F>> eval_points(3);
    
    for(int i = 0; i < r.size()-(int)log2(N)-(int)log2(vectors); i++){
        eval_points[0].push_back(r[i]);
    }
    for(int i = eval_points[0].size(); i < r.size()-(int)log2(N); i++){
        eval_points[1].push_back(r[i]);
    }
    for(int i = r.size()-(int)log2(N); i < r.size(); i++){
        eval_points[2].push_back(r[i]);
    }
    pt_cp.end();
    
    return make_pair(sum,eval_points);
}

// New version of multiplication tree prover that takes as input vectors of different size
void prove_product_opt(vector<vector<F>> &input, vector<F> &output, int N){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
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
    prove_product(new_input,temp_out,F(0),{},N);
    int ctr = 0;
    if(rank == 0){
        output.resize(input.size(),F(1));
        for(int i = 0; i < input.size(); i++){
            for(int j = 0; j < input[i].size()/size; j++)output[i] *= temp_out[ctr++];
        }
    }
    

}


void _reduce_R1CS_matrixes(size_t size, vector<F> r, vector<F> &RA, vector<F> &RB, vector<F> &RC, int N){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    
    vector<F> r1,r2,beta1,beta2;
    for(int i = 0; i < r.size() - (int)log2(N); i++){
        r1.push_back(r[i]);
    }
    for(int i = r.size() - (int)log2(N); i < r.size(); i++){
        r2.push_back(r[i]);
    }

    precompute_beta(r1,beta1);precompute_beta(r2,beta2);
    
    RA.resize(pA.size(),F(0));RB.resize(pB.size(),F(0));RC.resize(pC.size(),F(0));
    for(int i = 0; i < pA.size(); i++){
        if(pA[i].size()){
            //if(rank == 1) printf("%d,(%d,%d),(%d,%d,%d)\n",rank,pA[i][0].first,pA[i][0].first%RA.size(),pA[i][0].second,pA[i][0].second/(pA.size()/2),pA[i][0].second%(pA.size()/2));
            RA[pA[i][0].first%RA.size()] += beta1[pA[i][0].second%(pA.size()/2)]*beta2[pA[i][0].second/(pA.size()/2)];
        }
        if(pB[i].size()){
            //printf("> %d, %d\n",rank,pB[i][0].second);
            RB[pB[i][0].first%RB.size()] += beta1[pB[i][0].second%(pB.size()/2)]*beta2[pB[i][0].second/(pB.size()/2)];
        } 
        if(pC[i].size()){
            RC[pC[i][0].first%RC.size()] += beta1[pC[i][0].second%(pC.size()/2)]*beta2[pC[i][0].second/(pC.size()/2)];
        }
    }
}



void secret_share_vector(vector<F> &v, int _k, int k, int N){
    int ctr = 0;
    pt_cp.start();
    
    vector<vector<F>> data(N);
    for(int i = 0; i < data.size(); i++){
        data[i].resize(v.size()/k);
    }

    for(int i = 0; i < v.size()/k; i++){
        vector<F> buff(_k);
        for(int j = 0; j < k; j++){
            buff[j] = v[ctr++];
        }
        for(int j = k; j < _k; j++){
            buff[j] = 0;
        }
        fft(buff,(int)log2(buff.size()),true);
        buff.resize(2*N,F(0));
        fft(buff,(int)log2(buff.size()),false);
        for(int j = 0; j < N; j++){
            data[j][i] = buff[2*j + 1];
        }
    }

    vector<u64> buff_u64,buff_recv_u64;
    vector<F> buff = convert2vector(data);
    field_vector_serialize(buff,buff_u64);
    buff_recv_u64.resize(buff_u64.size(),(0));
    pt_cp.end();
    cm += 8*buff_u64.size()/1024.0;
    MPI_Alltoall(buff_u64.data(),buff_u64.size()/N,MPI_UINT64_T,buff_recv_u64.data(),buff_u64.size()/N,MPI_UINT64_T,MPI_COMM_WORLD);
    
    pt_cp.start();
    
    field_vector_deserialize(buff_recv_u64,v);
    pt_cp.end();
    
}



void compute_R1CS_betas(vector<F> r1, vector<F> r2, vector<sparse_eval_data> &data, vector<vector<F>> &beta1, vector<vector<F>> &beta2, int logm, int logn, int N){
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
    
    precompute_beta(r11,beta11);
    precompute_beta(r12,beta12);
    precompute_beta(r21,beta21);
    precompute_beta(r22,beta22);
    
    int ctr = 0;

    vector<F> b; precompute_beta(r2,b);
    for(int i = 0; i < data.size(); i++){
        beta1[i].resize(data[i].IDX1.size());
        for(int j = 0; j < data[i].IDX1.size(); j++){
            int idx1 = data[i].IDX1[j];
            int idx11 = idx1&mask1;
            int idx12 = idx1>>(logm/2);
            beta1[i][j] = beta11[idx11]*beta12[idx12];
            //ctr++;
            
        }
        beta2[i].resize(data[i].IDX2.size());        
        for(int j = 0; j < data[i].IDX2.size(); j++){
            int idx2 = data[i].IDX2[j];
            int idx21 = idx2&mask2;
            int idx22 = idx2>>(logn/2);
            beta2[i][j] = beta21[idx21]*beta22[idx22];
            //ctr++;
        }
    }
}

void  compute_base_betas(vector<F> r1,vector<F> r2, vector<F> &base_beta1, vector<F> &base_beta2, int N){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<F> r11,r12,r21,r22;
    
    for(int i  = 0; i < r1.size()-(int)log2(N); i++){
        r12.push_back(r1[i]);
    }
    for(int i = r12.size(); i < r1.size(); i++){
        r11.push_back(r1[i]);
    }
    
    for(int i  = 0; i < r2.size()-(int)log2(N); i++){
        r22.push_back(r2[i]);
    }
    for(int i = r22.size(); i < r2.size(); i++){
        r21.push_back(r2[i]);
    }
    
    precompute_beta(r12,base_beta1);
    precompute_beta(r22,base_beta2);
    F b1 = _beta(rank,  r11);
    F b2 = _beta(rank,  r21);
    
    for(int i = 0; i < base_beta1.size(); i++){
        base_beta1[i] = b1*base_beta1[i];
    }
    for(int i = 0; i < base_beta2.size(); i++){
        base_beta2[i] = b2*base_beta2[i];
    }
}


vector<pair<F,vector<F>>> distributed_accumulation(vector<vector<F>> &polys, vector<vector<vector<F>>> eval_points, vector<F> evals, int N){
    int rank,ctr = 0;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    pt_cp.start();
    vector<F> v1,v2,b;
    vector<F> r;
    F y;
    r.push_back(hash_to_field(evals));
    y = r[0]*evals[0];
    for(int i = 1; i < polys.size(); i++){
        r.push_back(hash_to_field({r[i-1]}));
        y += r[i]*evals[i];
    }
    
    for(int i = 0; i < polys.size(); i++){
        v1.insert(v1.end(),polys[i].begin(),polys[i].end());
    }
    v2.resize(v1.size());
    precompute_beta(eval_points[0][0],b);
    F _b = _beta(rank,eval_points[0][2]);
    for(int i = 0; i < b.size(); i++){
        b[i] = _b*b[i];
    }
    for(int i = 0; i < 3; i++){
        for(int j = 0; j < polys[i].size(); j++){
            v2[ctr] = r[i]*b[j];
            ctr++;
        }
    }
    b.clear();
    precompute_beta(eval_points[1][0],b);
    _b = _beta(rank,eval_points[1][2]);
    for(int i = 0; i < b.size(); i++){
        b[i] = _b*b[i];
    }
    for(int i = 3; i < 15; i++){
        for(int j = 0; j < polys[i].size(); j++){
            v2[ctr] = r[i]*b[j];
            ctr++;
        }
    }
    b.clear();
    precompute_beta(eval_points[2][0],b);
    _b = _beta(rank,eval_points[2][2]);
    for(int i = 0; i < b.size(); i++){
        b[i] = _b*b[i];
    }
    for(int i = 15; i < 18; i++){
        for(int j = 0; j < polys[i].size(); j++){
            v2[ctr] = r[i]*b[j];
            ctr++;
        }
    }
    v1.resize(next_pow2(v1.size()),F(0));
    v2.resize(next_pow2(v2.size()),F(0));
    pt_cp.end();
    
    vector<pair<F,vector<F>>> claim = _quadratic_sumcheck(y,v1,v2,N);
    pt_cp.start();
    
    if(rank == 0){
        vector<F> claimed_r1,claimed_r2;
        for(int i = 0; i < (int)log2(polys[0].size()); i++){
            claimed_r1.push_back(claim[0].second[i]);
        }
        for(int i = 0; i < (int)log2(N); i++){
            claimed_r1.push_back(claim[0].second[claim[0].second.size()-(int)log2(N)+i]);
        }
        for(int i = (int)log2(polys[0].size()); i < claim[0].second.size()-(int)log2(N); i++){
            claimed_r1.push_back(claim[0].second[i]);
        }

        for(int i = 0; i < (int)log2(polys[3].size()); i++){
            claimed_r2.push_back(claim[0].second[i]);
        }
        for(int i = 0; i < (int)log2(N); i++){
            claimed_r2.push_back(claim[0].second[claim[0].second.size()-(int)log2(N)+i]);
        }
        for(int i = (int)log2(polys[3].size()); i < claim[0].second.size()-(int)log2(N); i++){
            claimed_r2.push_back(claim[0].second[i]);
        }

        vector<F> partial_poly(32,F(0));
        
        vector<F> _r = eval_points[0][0];_r.insert(_r.end(),eval_points[0][2].begin(),eval_points[0][2].end());
        _b = beta_identity(_r,claimed_r1);
        for(int i = 0; i < 3; i++){
            partial_poly[i] = r[i]*_b;
        }
        _r = eval_points[1][0];_r.insert(_r.end(),eval_points[1][2].begin(),eval_points[1][2].end());
        _b = beta_identity(_r,claimed_r2);
        for(int i = 3; i < 15; i++){
            partial_poly[i] = r[i]*_b;
        }
        _r = eval_points[2][0];_r.insert(_r.end(),eval_points[2][2].begin(),eval_points[2][2].end());
        _b = beta_identity(_r,claimed_r2);
        for(int i = 15; i < 18; i++){
            partial_poly[i] = r[i]*_b;
        }

        int pos = 0;
        for(int i = 0; i < 3; i++){
            F prod = get_offset_product(N*polys[i].size(),pos,claimed_r1);
            pos += N*polys[i].size();
            partial_poly[i] *= prod;
        }
        for(int i = 3; i < 18; i++){
            F prod = get_offset_product(N*polys[i].size(),pos,claimed_r2);
            pos += N*polys[i].size();
            partial_poly[i] *= prod;
        }
        for(int i = 0; i < partial_poly.size(); i++){
            claim[1].first -= partial_poly[i];
        }
        printf("%lld,%lld\n",claim[1].first.real,claim[1].first.img);
        if(F(0) != claim[1].first){
            printf("Error in final eval\n");
        }

    }
    pt_cp.end();
    
    return claim;
}


void compute_transcript(vector<vector<F>> &Tr, vector<sparse_eval_data> &data, vector<F> challenges, vector<vector<F>> &beta1, vector<vector<F>> &beta2,
                    vector<F> r1, vector<F> r2, int N){
    int rank;
    vector<F> base_beta1,base_beta2;
    compute_base_betas(r1,r2,base_beta1,base_beta2,N);
    
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    for(int j = 0; j < data.size(); j++){
        Tr[2*j].resize(next_pow2(data[j].IDX1.size()),F(1));
        Tr[2*j+1].resize(next_pow2(data[j].IDX1.size()),F(1));
        for(int i = 0; i < data[j].IDX1.size(); i++){
            Tr[2*j][i] = challenges[0]*beta1[j][i] +  challenges[1]*F(data[j].RD1[i]) + challenges[2]*F(data[j].IDX1[i]) + F(1);
            Tr[2*j+1][i] = challenges[0]*beta1[j][i] +  challenges[1]*F(data[j].WR1[i]) + challenges[2]*F(data[j].IDX1[i]) + F(1);
        }
    }
    for(int j = 0; j < data.size(); j++){
        Tr[2*j+6].resize(next_pow2(data[0].IDX2.size()),F(1));
        Tr[2*j+1+6].resize(next_pow2(data[0].IDX2.size()),F(1));
        for(int i = 0; i < data[j].IDX2.size(); i++){
            Tr[2*j+6][i] = challenges[0]*beta2[j][i] +  challenges[1]*F(data[j].RD2[i]) + challenges[2]*F(data[j].IDX2[i]) + F(1);
            Tr[2*j+1+6][i] = challenges[0]*beta2[j][i] +  challenges[1]*F(data[j].WR2[i]) + challenges[2]*F(data[j].IDX2[i]) + F(1);
        }
    }
    for(int j = 0; j < data.size(); j++){
        Tr[2*j+12].resize(next_pow2(data[0].FINAL_FR1.size()),F(1));
        Tr[2*j+1+12].resize(next_pow2(data[0].FINAL_FR1.size()),F(1));
    
        for(int i = 0; i < data[j].FINAL_FR1.size(); i++){
            Tr[2*j+0+12][i] = challenges[0]*base_beta1[i] +  challenges[2]*F(rank*data[j].FINAL_FR1.size() + i) + F(1);
            Tr[2*j+1+12][i] = challenges[0]*base_beta1[i] +  challenges[1]*F(data[j].FINAL_FR1[i]) + challenges[2]*F(rank*data[j].FINAL_FR1.size() + i) + F(1);
        }
    }
    for(int j = 0; j < data.size(); j++){
        Tr[2*j+18].clear();Tr[2*j+1].clear();
        Tr[2*j+18].resize(next_pow2(data[0].FINAL_FR2.size()),F(1));
        Tr[2*j+1+18].resize(next_pow2(data[0].FINAL_FR2.size()),F(1));
        for(int i = 0; i < data[j].FINAL_FR2.size(); i++){
            Tr[2*j+18][i] = challenges[0]*base_beta2[i] +  challenges[2]*F(rank*data[j].FINAL_FR2.size() + i) + F(1);
            Tr[2*j+1+18][i] = challenges[0]*base_beta2[i] +  challenges[1]*F(data[j].FINAL_FR2[i]) + challenges[2]*F(rank*data[j].FINAL_FR2.size() + i) + F(1);
        }
    }
}

void sort_transcript(vector<vector<F>> &Tr, vector<int> &order){
    // Create a vector of pairs to store (value, original_index)
    std::vector<std::pair<int, int>> sizes;
    for(int i = 0; i < Tr.size(); i++){
        sizes.push_back(make_pair(Tr.size(),i));
    }
    

    // Sort the indexed_vector based on the values (first element of the pair)
    // By default, std::sort sorts pairs based on the first element, then the second if first elements are equal.
    std::sort(sizes.begin(), sizes.end());
    reverse(sizes.begin(),sizes.end());
    for(int i = 0; i < sizes.size(); i++) order.push_back(sizes[i].second);
    
    vector<vector<F>> temp;
    for(int i = 0; i < sizes.size(); i++) temp.push_back(Tr[sizes[i].second]);
    Tr = temp;
}


void _prove_sparse_eval_opt(F y, F a, F b, F c, vector<vector<F>> &beta1, vector<vector<F>> &beta2, vector<sparse_eval_data> &data, 
                        vector<F> r1, vector<F> r2, int N){
    
    vector<vector<F>> Tr(24);
    vector<int> order;
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    pt_cp.start();
    vector<F> challenges(3);
    clock_t t1 = clock();
    for(int i = 0; i < 3; i++) challenges[i] = hash_to_field({0}); 
    
    compute_transcript(Tr, data, challenges, beta1, beta2, r1, r2, N);
    sort_transcript(Tr, order);
}



pair<F,vector<F>> _prove_sparse_eval(F y, F a, F b, F c, vector<vector<F>> &beta1, vector<vector<F>> &beta2, vector<sparse_eval_data> &data, 
                        vector<F> r1, vector<F> r2, 
                        int N){
    
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    pt_cp.start();
    vector<F> challenges(3);
    clock_t t1 = clock();
    for(int i = 0; i < 3; i++) challenges[i] = hash_to_field({0}); 
    
    
    vector<vector<F>> Tr(12);
    vector<vector<F>> polys,acc_polys(18);
    vector<vector<vector<F>>> acc_eval_points;
    vector<F> acc_evals;
    for(int j = 0; j < data.size(); j++){
        Tr[2*j].resize(next_pow2(data[j].IDX1.size()),F(1));
        Tr[2*j+1].resize(next_pow2(data[j].IDX1.size()),F(1));
        for(int i = 0; i < data[j].IDX1.size(); i++){
            Tr[2*j][i] = challenges[0]*beta1[j][i] +  challenges[1]*F(data[j].RD1[i]) + challenges[2]*F(data[j].IDX1[i]) + F(1);
            Tr[2*j+1][i] = challenges[0]*beta1[j][i] +  challenges[1]*F(data[j].WR1[i]) + challenges[2]*F(data[j].IDX1[i]) + F(1);
        }
    }
    for(int j = 0; j < data.size(); j++){
        Tr[2*j+6].resize(next_pow2(data[0].IDX2.size()),F(1));
        Tr[2*j+1+6].resize(next_pow2(data[0].IDX2.size()),F(1));
        for(int i = 0; i < data[j].IDX2.size(); i++){
            Tr[2*j+6][i] = challenges[0]*beta2[j][i] +  challenges[1]*F(data[j].RD2[i]) + challenges[2]*F(data[j].IDX2[i]) + F(1);
            Tr[2*j+1+6][i] = challenges[0]*beta2[j][i] +  challenges[1]*F(data[j].WR2[i]) + challenges[2]*F(data[j].IDX2[i]) + F(1);
        }
    }
    vector<F> output1,output2,output3;
    pt_cp.end();
    
    pair<F,vector<vector<F>>> claims = prove_product(Tr, output1, F(0), {}, N);
    vector<F> v1,v2;
    pt_cp.start();
    
    precompute_beta(claims.second[0],v1);
    precompute_beta(claims.second[2],v2);
    vector<vector<F>> eval_points1 = claims.second;
    for(int i = 0; i < data.size(); i++){
        polys.push_back(beta1[i]);
        polys.push_back(convert_to_field(data[i].RD1));
        polys.push_back(convert_to_field(data[i].IDX1));
        acc_polys[2*i+3] = polys[3*i+1];
        acc_polys[2*i+1+3] = polys[3*i+2];

    }
    for(int i = 0; i < data.size(); i++){
        polys.push_back(beta2[i]);
        polys.push_back(convert_to_field(data[i].RD2));
        polys.push_back(convert_to_field(data[i].IDX2));        
        acc_polys[2*i+6+3] = polys[3*i+1+9];
        acc_polys[2*i+1+6+3] = polys[3*i+2+9];
    }
    pt_cp.end();
    
    vector<F> evals = batch_distributed_eval(polys,v1,v2,N);
    pt_cp.start();
    
    vector<F> beta_evals,evals1;
    vector<F> betas_r = claims.second[0];
    vector<F> temp_r;
    
    for(int i = 0; i < (int)log2(next_pow2(2*beta1.size())); i++){
        betas_r.push_back(hash_to_field({0}));
        temp_r.push_back(betas_r[betas_r.size()-1]); 
    }
    betas_r.insert(betas_r.end(),claims.second[2].begin(),claims.second[2].end());
    
    //vector<F> evals2 = batch_distributed_eval(Tr,v1,v2,N);
    for(int i = 0; i < data.size();i++){
        beta_evals.push_back(evals[3*i]);
        evals1.push_back(evals[3*i+1]);
        evals1.push_back(evals[3*i+2]);
    }
    for(int i = 0; i < data.size();i++){
        beta_evals.push_back(evals[3*i+9]);
        evals1.push_back(evals[3*i+1+9]);
        evals1.push_back(evals[3*i+2+9]);
    }
    
    
    
    if(rank == 0){
        vector<F> Tr_evals(12,F(0));
        for(int i = 0; i < data.size();i++){
            Tr_evals[2*i] = challenges[0]*evals[3*i] +  challenges[1]*evals[3*i+1] + challenges[2]*evals[3*i+2] + F(1);
            Tr_evals[2*i+1] = Tr_evals[2*i] +  challenges[1];
        }
        for(int i = 0; i < data.size();i++){
            Tr_evals[2*i+6] = challenges[0]*evals[3*i+9] +  challenges[1]*evals[3*i+1+9] + challenges[2]*evals[3*i+2+9] + F(1);
            Tr_evals[2*i+1+6] = Tr_evals[2*i+6] +  challenges[1];
        }
        
        Tr_evals.resize(16,F(0));
        if(evaluate_vector(Tr_evals,claims.second[1]) != claims.first){
            printf("Sparse Eval Error 1\n");
        }
    }

    vector<F> base_beta1,base_beta2;
    compute_base_betas(r1,r2,base_beta1,base_beta2,N);

    Tr.clear();Tr.resize(6);
    for(int j = 0; j < data.size(); j++){
        Tr[2*j].clear();Tr[2*j+1].clear();
        Tr[2*j].resize(next_pow2(data[0].FINAL_FR1.size()),F(1));
        Tr[2*j+1].resize(next_pow2(data[0].FINAL_FR1.size()),F(1));
    
        for(int i = 0; i < data[j].FINAL_FR1.size(); i++){
            Tr[2*j+0][i] = challenges[0]*base_beta1[i] +  challenges[2]*F(rank*data[j].FINAL_FR1.size() + i) + F(1);
            Tr[2*j+1][i] = challenges[0]*base_beta1[i] +  challenges[1]*F(data[j].FINAL_FR1[i]) + challenges[2]*F(rank*data[j].FINAL_FR1.size() + i) + F(1);
        }
    }
    pt_cp.end();
    
    claims = prove_product(Tr, output2, F(0), {}, N);
    pt_cp.start();
    
    polys.clear();
    for(int i = 0; i < data.size(); i++){
        polys.push_back(convert_to_field(data[i].FINAL_FR1));
        acc_polys[i+15] = polys[i];    
    }
    v1.clear();v2.clear();
    precompute_beta(claims.second[0],v1);
    precompute_beta(claims.second[2],v2);
    pt_cp.end();
    vector<F> evals2 = batch_distributed_eval(polys,v1,v2,N);
    vector<vector<F>> eval_points2 = claims.second;


    pt_cp.start();
    
    Tr.clear();Tr.resize(6);
    for(int j = 0; j < data.size(); j++){
        Tr[2*j].clear();Tr[2*j+1].clear();
        Tr[2*j].resize(next_pow2(data[0].FINAL_FR2.size()),F(1));
        Tr[2*j+1].resize(next_pow2(data[0].FINAL_FR2.size()),F(1));
        for(int i = 0; i < data[j].FINAL_FR2.size(); i++){
            Tr[2*j][i] = challenges[0]*base_beta2[i] +  challenges[2]*F(rank*data[j].FINAL_FR2.size() + i) + F(1);
            Tr[2*j+1][i] = challenges[0]*base_beta2[i] +  challenges[1]*F(data[j].FINAL_FR2[i]) + challenges[2]*F(rank*data[j].FINAL_FR2.size() + i) + F(1);
        }
    }
    pt_cp.end();
    
    claims = prove_product(Tr, output3, F(0), {}, N);
    pt_cp.start();
    
    polys.clear();
    for(int i = 0; i < data.size(); i++){
        polys.push_back(convert_to_field(data[i].FINAL_FR2));
        acc_polys[i] = polys[i];    
    }
    v1.clear();v2.clear();
    precompute_beta(claims.second[0],v1);
    precompute_beta(claims.second[2],v2);
    pt_cp.end();
    vector<F> evals3 = batch_distributed_eval(polys,v1,v2,N);
    vector<vector<F>> eval_points3 = claims.second;
    pt_cp.start();
    
    
    if(rank == 0){
        //printf("%d\n",output1.size());
        for(int i = 0; i < 3; i++){
            if(output1[2*i]*output2[2*i+1] != output1[2*i+1]*output2[2*i+0]){
                printf("Error phase 2 %d\n",i);
            }
        }
        for(int i = 0; i < 3; i++){
            if(output1[2*i+6]*output3[2*i+1] != output1[2*i+1+6]*output3[2*i+0]){
                printf("Error phase 2 %d\n",i);
            }
        }
    }
    acc_eval_points.push_back(eval_points3);
    acc_eval_points.push_back(eval_points1);
    acc_eval_points.push_back(eval_points2);
    acc_evals = evals3;
    acc_evals.insert(acc_evals.end(),evals1.begin(),evals1.end());
    acc_evals.insert(acc_evals.end(),evals2.begin(),evals2.end());
    pt_cp.end();
    
    distributed_accumulation(acc_polys, acc_eval_points, acc_evals, N);
    
    pt_cp.start();
    /// Need to do the final sumcheck 
    vector<F> v3,ones(N,1);
    
    v1.clear();v2.clear();
    for(int i = 0; i < beta1.size(); i++){
        v1.insert(v1.end(),beta1[i].begin(),beta1[i].end());
        v2.insert(v2.end(),beta2[i].begin(),beta2[i].end());
    }
    v1.resize(next_pow2(v1.size()),F(0));v2.resize(next_pow2(v2.size()),F(0));
    
    
    int ca = 0,cb = 0,cc = 0;
    v3.resize(4*next_pow2(real_idx_dim[0])/N,F(0));
    if(rank != N-1){
        int ctr = 0;
        for(int i = 0 ; i < next_pow2(real_idx_dim[0])/N; i++){
            v3[ctr] = a;
            ctr++;
        }
        for(int i = 0 ; i < next_pow2(real_idx_dim[1])/N; i++){
            v3[ctr] = b;
            ctr++;
        }
        for(int i = 0 ; i < next_pow2(real_idx_dim[2])/N; i++){
            v3[ctr] = c;
            ctr++;
        }
    }else{
        int ctr = 0;
        for(int i = 0 ; i < real_idx_dim[0] - (N-1)*next_pow2(real_idx_dim[0])/N; i++){
            v3[ctr] = a;
            ctr++;
        }
        ctr = next_pow2(real_idx_dim[0])/N;
        for(int i = 0 ; i < real_idx_dim[1] - (N-1)*next_pow2(real_idx_dim[1])/N; i++){
            v3[ctr] = b;
            ctr++;
        }
        ctr = 2*next_pow2(real_idx_dim[1])/N;
        
        for(int i = 0 ; i < real_idx_dim[2] - (N-1)*next_pow2(real_idx_dim[2])/N; i++){
            v3[ctr] = c;
            ctr++;
        }
    }    
    pt_cp.end();
    
    vector<pair<F,vector<F>>>  beta_evals2 =  _cubic_sumcheck(y,v1,v2,v3,ones,N);
    
    beta_evals.resize(next_pow2(beta_evals.size()),F(0));
    return make_pair(evaluate_vector(beta_evals,temp_r),betas_r);
}
