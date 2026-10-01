#include "coPCS.h"
#include "Fiat_Shamir.h"
#include "Distributed_Sumcheck.h"
#include "timer.hpp"
#include "accountability/PVIA.hpp"
#include "accountability/JointPackedPreprocessing.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <cstdlib>
extern int rate;
extern timer pt_cp,vt;
extern double cm;
extern int com_rounds;
extern int PC_offset;

namespace {
void enforce_encoding_stage2_release_gate() {
    auto& rt = pvia::Runtime::instance();
    if (!rt.enabled()) return;
    if (rt.pre_release_gate(
            "encoding_stage2_codeword", pvia::Phase::ENCODING, 2))
        return;
    rt.handle_global_failure(
        "encoding_stage2_codeword", pvia::Phase::ENCODING, 2);
    std::exit(15);
}

static vector<F> pvia_build_merkle_reply(const vector<F>& codeword, size_t query_pos) {
    if (codeword.size() < 8 || codeword.size() % 4 != 0) return {};
    const size_t half = codeword.size()/2;
    if (query_pos >= codeword.size()) return {};
    const size_t p0 = query_pos < half ? query_pos : query_pos-half;
    const size_t p1 = query_pos < half ? query_pos+half : query_pos;
    vector<F> out = {codeword[p0], codeword[p1]};
    const size_t b0 = (p0/4)*4, b1 = (p1/4)*4;
    out.insert(out.end(), codeword.begin()+b0, codeword.begin()+b0+4);
    out.insert(out.end(), codeword.begin()+b1, codeword.begin()+b1+4);
    return out;
}

static bool pvia_reply_leafs_match_tree(vector<vector<_hash>>& tree,
                                         size_t query_pos,
                                         const vector<F>& proof) {
    if (proof.size() < 10 || tree.empty() || tree[0].empty()) return false;
    const size_t total = tree[0].size()*4;
    if (query_pos >= total) return false;
    const size_t half = total/2;
    const size_t p0 = query_pos < half ? query_pos : query_pos-half;
    const size_t p1 = query_pos < half ? query_pos+half : query_pos;
    if (proof[0] != proof[2 + (p0%4)] || proof[1] != proof[6 + (p1%4)]) return false;
    auto leaf_ok = [&](size_t pos, size_t off) {
        const _hash h = merkle_tree::hash_leaf_blake(proof.data()+off);
        return std::memcmp(h.arr, tree[0][pos/4].arr, 32) == 0;
    };
    return leaf_ok(p0,2) && leaf_ok(p1,6);
}

} // namespace

void distributed_MT(vector<F> &data, MT &Com, int N){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    pt_cp.start();
    merkle_tree::merkle_tree_prover::MT_commit_Blake(
        data.data(),Com.Base_MT, data.size());
    pt_cp.end();
    com_rounds++;

    const bool pvia_on = pvia::Runtime::instance().enabled();
    auto digest_words = [](const uint8_t* bytes) {
        vector<u64> words(4, 0);
        std::memcpy(words.data(), bytes, 32);
        return words;
    };
    std::vector<pvia::OperationRef> commit_predecessors;
    pvia::StateId commit_state_dependency = 0;
    if (pvia_on) {
        const auto predecessor =
            pvia::Runtime::instance().consume_next_commit_predecessor();
        if (predecessor.object_id != 0)
            commit_predecessors.push_back(predecessor);
        commit_state_dependency =
            pvia::Runtime::instance().consume_next_commit_state_dependency();
        if (commit_state_dependency == 0) {
            commit_state_dependency = pvia::Runtime::instance().import_state(
                "oracle_commit_input", pvia::Phase::ORACLE, data);
        }
    }

    if(rank != 0){
        std::array<uint8_t, 32> root_to_send{};
        std::memcpy(root_to_send.data(),
                    Com.Base_MT[Com.Base_MT.size()-1][0].arr, 32);

        std::array<u64, pvia::META_WORDS> root_meta{};
        if (pvia_on) {
            const vector<u64> expected_root =
                digest_words(root_to_send.data());
            auto& rt = pvia::Runtime::instance();
            const pvia::RecordId commit_record = rt.register_word_operation(
                pvia::Phase::ORACLE, 0, pvia::Obligation::COMMIT,
                expected_root, commit_predecessors);
            if (commit_state_dependency != 0)
                rt.bind_state_dependencies(
                    commit_record,
                    std::vector<pvia::StateId>{commit_state_dependency});
            rt.bind_relation_kernel(
                commit_record, pvia::AuditRelationKernel::ORACLE_MERKLE_COMMIT);
            rt.bind_public_word_aux(
                commit_record, pvia::AuditPublicAuxKind::COMMIT_DOMAIN,
                vector<u64>{static_cast<u64>(data.size())});
            rt.activate_words(commit_record, expected_root);
            root_meta = rt.make_pending_meta(expected_root, false);

            // Transcript-direct publication consistency: metadata fixes the root
            // before the bytes sent to rank 0 may be substituted.
            const vector<u64> actual_root =
                digest_words(root_to_send.data());
            pvia::Runtime::instance().seal_transfer_meta(root_meta, actual_root);
            pvia::Runtime::instance().observe_outgoing_transfer(root_meta, actual_root);
            pvia::Runtime::instance().observe_local_payload(actual_root);
            MPI_Send(root_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                     0, pvia::META_TAG, MPI_COMM_WORLD);
        }

        MPI_Request req;
        MPI_Isend(root_to_send.data(),32,MPI_UINT8_T,
                  0,0,MPI_COMM_WORLD,&req);
        MPI_Wait(&req,MPI_STATUS_IGNORE);
        if (pvia_on) pvia::Runtime::instance().consume_pending();
        //MPI_Send(Com.Base_MT[Com.Base_MT.size()-1][0].arr,32,MPI_UINT8_T,0,0,MPI_COMM_WORLD);
    }else{
        vector<_hash> recv_hashes(N);
        vector<MPI_Request> req(N);
        recv_hashes[0] = Com.Base_MT[Com.Base_MT.size()-1][0];

        if (pvia_on) {
            const vector<u64> local_root =
                digest_words(recv_hashes[0].arr);
            auto& rt = pvia::Runtime::instance();
            const pvia::RecordId commit_record = rt.register_word_operation(
                pvia::Phase::ORACLE, 0, pvia::Obligation::COMMIT,
                local_root, commit_predecessors);
            if (commit_state_dependency != 0)
                rt.bind_state_dependencies(
                    commit_record,
                    std::vector<pvia::StateId>{commit_state_dependency});
            rt.bind_relation_kernel(
                commit_record, pvia::AuditRelationKernel::ORACLE_MERKLE_COMMIT);
            rt.bind_public_word_aux(
                commit_record, pvia::AuditPublicAuxKind::COMMIT_DOMAIN,
                vector<u64>{static_cast<u64>(data.size())});
            rt.activate_words(commit_record, local_root);
            const auto local_meta = rt.make_pending_meta(local_root, false);
            rt.observe_local_payload(local_root);
            rt.consume_pending();
        }

        for(int i = 1; i < N; i++){
            MPI_Irecv(recv_hashes[i].arr,32,MPI_UINT8_T,
                      i,0,MPI_COMM_WORLD,&req[i]);
            //MPI_Recv(recv_hashes[i].arr,32,MPI_UINT8_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        }
        for(int i = 1; i < N; i++){
            std::array<u64, pvia::META_WORDS> remote_meta{};
            if (pvia_on) {
                MPI_Recv(remote_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                         i, pvia::META_TAG, MPI_COMM_WORLD,
                         MPI_STATUS_IGNORE);
            }
            MPI_Wait(&req[i],MPI_STATUS_IGNORE);
            if (pvia_on) {
                const vector<u64> actual_root =
                    digest_words(recv_hashes[i].arr);
                pvia::Runtime::instance().observe_remote_meta(
                    i, remote_meta, actual_root);
            }
        }
        Com.Root_MT.resize((int)log2(N)+1);
        Com.Root_MT[0] = recv_hashes;
        merkle_tree::merkle_tree_prover::create_tree_blake(
            N,Com.Root_MT,sizeof(__hhash_digest),true);
    }
    if (pvia_on) {
        pvia::Runtime::instance().seal_checkpoint_instance(
            pvia::Phase::ORACLE, 0);
    }
}

void dummy_setup(vector<F> &R_shares, vector<vector<F>> &mask_shares, int N, int M, int k, int _k, int l){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id

    if (pvia::Runtime::instance().enabled()) {
        pvia::JointPackedPreprocessingResult setup_result;
        if (!pvia::generate_joint_packed_random_share(
                static_cast<size_t>(l), N, k, _k,
                0x5056505245574954ULL, &R_shares, &setup_result,
                MPI_COMM_WORLD) || !setup_result.ok) {
            if (rank == 0)
                printf("[PVIA][preprocessing] witness mask setup unavailable\n");
            std::exit(15);
        }

        if((int)log2(M/k)-1 <= (int)log2(next_pow2(l))){
            mask_shares.resize(1);
            if (!pvia::generate_joint_packed_random_share(
                    static_cast<size_t>(2*M/k), N, k, _k,
                    0x50565052454d3030ULL, &mask_shares[0], nullptr,
                    MPI_COMM_WORLD)) {
                if (rank == 0)
                    printf("[PVIA][preprocessing] opening mask setup unavailable\n");
                std::exit(15);
            }
        } else {
            mask_shares.resize((int)log2(M/k)-1-(int)log2(l));
            for(int i = 0; i < (int)mask_shares.size(); i++){
                const size_t count = i != (int)mask_shares.size()-1
                    ? static_cast<size_t>(3*l+2)
                    : static_cast<size_t>(next_pow2(3*l+M/k)/(1<<i));
                const uint64_t domain =
                    0x50565052454d1000ULL + static_cast<uint64_t>(i);
                if (!pvia::generate_joint_packed_random_share(
                        count, N, k, _k, domain, &mask_shares[i], nullptr,
                        MPI_COMM_WORLD)) {
                    if (rank == 0)
                        printf("[PVIA][preprocessing] opening mask level unavailable\n");
                    std::exit(15);
                }
            }
        }
        return;
    }
     
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

    // PVIA first-stage ENCODE/DERIVE block.  The complete encoded matrix is
    // registered before it is split into one destination segment per peer.
    if (pvia::Runtime::instance().enabled()) {
        vector<F> first_stage_input = convert2vector(data);
        const pvia::StateId first_stage_state =
            pvia::Runtime::instance().import_state(
                "encoding_first_stage_input", pvia::Phase::ENCODING,
                first_stage_input);
        pvia::RecordId derive_record =
            pvia::Runtime::instance().prepare_vector(
                pvia::Phase::ENCODING, 0,
                pvia::Obligation::DERIVE, shares_v);
        pvia::Runtime::instance().bind_state_dependencies(
            derive_record, std::vector<pvia::StateId>{first_stage_state});
        pvia::Runtime::instance().bind_relation_kernel(
            derive_record, pvia::AuditRelationKernel::ENCODING_FIRST_STAGE);
        pvia::Runtime::instance().activate_vector(derive_record, shares_v);
        vector<u64> derive_payload;
        field_vector_serialize(shares_v, derive_payload);
        pvia::Runtime::instance().observe_local_payload(derive_payload);
        pvia::Runtime::instance().consume_pending();
    }
    
    field_vector_serialize(shares_v,send_buff);
    recv_buff.resize(send_buff.size());
    cm += 8*send_buff.size()/1024.0;        
    com_rounds++;

    // Each all-to-all slice gets an independent SEND label.  Metadata is
    // created before an optional transfer substitution and checked by the
    // corresponding receiver against the bytes it actually obtains.
    vector<u64> pvia_meta_send, pvia_meta_recv;
    const bool pvia_on = pvia::Runtime::instance().enabled();
    const size_t pvia_chunk_words = send_buff.size()/N;
    pvia::RecordId assemble_record = 0;
    std::vector<pvia::OperationRef> assemble_predecessors;
    if (pvia_on) {
        pvia_meta_send.resize(N*pvia::META_WORDS);
        pvia_meta_recv.resize(N*pvia::META_WORDS);
        for (int dst = 0; dst < N; dst++) {
            vector<u64> segment(
                send_buff.begin() + dst*pvia_chunk_words,
                send_buff.begin() + (dst+1)*pvia_chunk_words);
            const uint64_t object_id =
                pvia::Runtime::instance().allocate_object_id();
            auto meta = pvia::Runtime::instance().make_direct_meta(
                pvia::Phase::ENCODING, 0, pvia::Obligation::SEND,
                object_id, segment, false);
            std::copy(meta.begin(), meta.end(),
                      pvia_meta_send.begin() + dst*pvia::META_WORDS);
        }


        for (int dst = 0; dst < N; dst++) {
            vector<u64> segment(
                send_buff.begin() + dst*pvia_chunk_words,
                send_buff.begin() + (dst+1)*pvia_chunk_words);
            std::array<u64, pvia::META_WORDS> meta{};
            std::copy(pvia_meta_send.begin() + dst*pvia::META_WORDS,
                      pvia_meta_send.begin() + (dst+1)*pvia::META_WORDS,
                      meta.begin());
            pvia::Runtime::instance().seal_transfer_meta(meta, segment);
            std::copy(meta.begin(), meta.end(),
                      pvia_meta_send.begin() + dst*pvia::META_WORDS);
            pvia::Runtime::instance().observe_direct_local(meta, segment);
        }
    }

    //myAlltoAll(send_buff, recv_buff, N, send_buff.size());
    //MPI_Alltoall(send_buff.data(),send_buff.size()/N,MPI_UINT64_T,recv_buff.data(),recv_buff.size()/N,MPI_UINT64_T,MPI_COMM_WORLD);
    MPI_Request req[2];
    int req_count = 0;
    if (pvia_on) {
        MPI_Ialltoall(pvia_meta_send.data(), pvia::META_WORDS, MPI_UINT64_T,
                      pvia_meta_recv.data(), pvia::META_WORDS, MPI_UINT64_T,
                      MPI_COMM_WORLD, &req[req_count++]);
    }
    MPI_Ialltoall(send_buff.data(),send_buff.size()/N,MPI_UINT64_T,
                  recv_buff.data(),recv_buff.size()/N,MPI_UINT64_T,
                  MPI_COMM_WORLD,&req[req_count++]);
    MPI_Waitall(req_count, req, MPI_STATUSES_IGNORE);

    if (pvia_on) {
        for (int sender = 0; sender < N; sender++) {
            vector<u64> segment(
                recv_buff.begin() + sender*pvia_chunk_words,
                recv_buff.begin() + (sender+1)*pvia_chunk_words);
            std::array<u64, pvia::META_WORDS> meta{};
            std::copy(pvia_meta_recv.begin() + sender*pvia::META_WORDS,
                      pvia_meta_recv.begin() + (sender+1)*pvia::META_WORDS,
                      meta.begin());
            pvia::Runtime::instance().observe_remote_meta(
                sender, meta, segment);
            pvia::OperationRef send_ref;
            send_ref.owner = static_cast<uint32_t>(sender);
            send_ref.object_id = meta[6];
            assemble_predecessors.push_back(send_ref);
        }
        pvia::Runtime::instance().seal_checkpoint_instance(
            pvia::Phase::ENCODING, 0);
    }

    field_vector_deserialize(recv_buff,row);
    if (pvia_on) {
        const pvia::StateId received_row_state =
            pvia::Runtime::instance().import_state(
                "encoding_received_row", pvia::Phase::ENCODING, row);

        // RECEIVE is now fixed; ASSEMBLE is a separate local obligation.
        assemble_record =
            pvia::Runtime::instance().register_vector_operation(
                pvia::Phase::ENCODING, 1,
                pvia::Obligation::ASSEMBLE, row, assemble_predecessors);
        pvia::Runtime::instance().bind_state_dependencies(
            assemble_record, std::vector<pvia::StateId>{received_row_state});
        pvia::Runtime::instance().bind_relation_kernel(
            assemble_record, pvia::AuditRelationKernel::ENCODING_ASSEMBLE);
        pvia::Runtime::instance().bind_public_word_aux(
            assemble_record, pvia::AuditPublicAuxKind::ASSEMBLY_LAYOUT,
            vector<u64>{static_cast<u64>(N),
                        static_cast<u64>(pvia_chunk_words),
                        static_cast<u64>(recv_buff.size()),
                        static_cast<u64>(row.size())});
        pvia::Runtime::instance().activate_vector(assemble_record, row);
        vector<u64> assembled_payload;
        field_vector_serialize(row, assembled_payload);
        pvia::Runtime::instance().observe_local_payload(assembled_payload);
        pvia::Runtime::instance().consume_pending();
        pvia::Runtime::instance().seal_checkpoint_instance(
            pvia::Phase::ENCODING, 1);
    }

    row_data.resize(next_pow2(row.size()+l),0);
    // Input distribution emulation 
    //printf(">> %d\n",row.size());
    for(int j = 0; j < row.size(); j++){
        row_data[j] = row[j];
    }
    for(int j = 0 ; j < l; j++){
        row_data[j + row.size()] = R_shares[j]; 
    }
    pvia::StateId stage2_input_state = 0;
    if (pvia_on) {
        vector<F> stage2_input = row;
        stage2_input.insert(stage2_input.end(), R_shares.begin(), R_shares.end());
        stage2_input_state = pvia::Runtime::instance().import_state(
            "encoding_stage2_input", pvia::Phase::ENCODING, stage2_input);
    }
    encode_protocol_step2(row, R_shares, codeword);

    if (pvia_on) {
        // Bind the second-stage encoding output before it is consumed by the
        // oracle commitment.  A deliberate ENCODE_STAGE2 fault therefore
        // remains distinct from first-stage transfer/assembly faults.
        std::vector<pvia::OperationRef> stage2_predecessors;
        if (assemble_record != 0) {
            pvia::OperationRef assemble_ref;
            assemble_ref.owner = static_cast<uint32_t>(rank);
            assemble_ref.object_id = assemble_record;
            stage2_predecessors.push_back(assemble_ref);
        }
        pvia::RecordId stage2_record =
            pvia::Runtime::instance().register_vector_operation(
                pvia::Phase::ENCODING, 2,
                pvia::Obligation::DERIVE, codeword, stage2_predecessors);
        if (stage2_input_state != 0)
            pvia::Runtime::instance().bind_state_dependencies(
                stage2_record, std::vector<pvia::StateId>{stage2_input_state});
            pvia::Runtime::instance().bind_relation_kernel(
                stage2_record, pvia::AuditRelationKernel::ENCODING_STAGE2);
        pvia::Runtime::instance().activate_vector(stage2_record, codeword);
        pvia::OperationRef commit_predecessor;
        commit_predecessor.owner = static_cast<uint32_t>(rank);
        commit_predecessor.object_id = stage2_record;
        pvia::Runtime::instance().set_next_commit_predecessor(
            commit_predecessor);
        vector<u64> codeword_payload;
        field_vector_serialize(codeword, codeword_payload);
        pvia::Runtime::instance().observe_local_payload(codeword_payload);
        pvia::Runtime::instance().consume_pending();
        pvia::Runtime::instance().seal_checkpoint_instance(
            pvia::Phase::ENCODING, 2);
        const pvia::StateId codeword_state =
            pvia::Runtime::instance().import_state(
                "encoding_stage2_codeword", pvia::Phase::ORACLE, codeword);
        pvia::Runtime::instance().set_next_commit_state_dependency(
            codeword_state);
    }
}



void commit(vector<F> &codeword, vector<F> &row_data, vector<F> &R_shares, MT &Com, int l, int k, int _k, int M, int N){
    int rank;
    vector<vector<F>> data;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    get_data(data,N,rank,k,_k,M/N);
    encode(codeword,row_data,data,R_shares,l,k,_k,M,N);
    enforce_encoding_stage2_release_gate();
    distributed_MT(codeword, Com,N);
}
// Commitment algorithm when given the secret shares
void commit(vector<F> &codeword, vector<F> &row_data, vector<F> &W_shares, vector<F> &R_shares, MT &Com, int l, int k, int _k, int N){
    pt_cp.start();
    std::vector<pvia::OperationRef> upstream_predecessors;
    pvia::StateId upstream_state_dependency = 0;
    if (pvia::Runtime::instance().enabled()) {
        const auto predecessor =
            pvia::Runtime::instance().consume_next_commit_predecessor();
        if (predecessor.object_id != 0)
            upstream_predecessors.push_back(predecessor);
        upstream_state_dependency =
            pvia::Runtime::instance().consume_next_commit_state_dependency();
    }
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
    if (pvia::Runtime::instance().enabled()) {
        vector<F> direct_input = W_shares;
        direct_input.insert(direct_input.end(), R_shares.begin(), R_shares.end());
        const pvia::StateId direct_input_state =
            pvia::Runtime::instance().import_state(
                "direct_commit_input", pvia::Phase::ENCODING, direct_input);
        pvia::RecordId rec =
            pvia::Runtime::instance().register_vector_operation(
                pvia::Phase::ENCODING, 2, pvia::Obligation::DERIVE,
                codeword, upstream_predecessors);
        std::vector<pvia::StateId> derive_dependencies{direct_input_state};
        if (upstream_state_dependency != 0)
            derive_dependencies.push_back(upstream_state_dependency);
        pvia::Runtime::instance().bind_state_dependencies(
            rec, derive_dependencies);
        pvia::Runtime::instance().bind_relation_kernel(
            rec, pvia::AuditRelationKernel::ENCODING_DIRECT_STAGE2);
        pvia::Runtime::instance().activate_vector(rec, codeword);
        pvia::OperationRef commit_predecessor;
        commit_predecessor.owner = static_cast<uint32_t>(pvia::Runtime::instance().rank());
        commit_predecessor.object_id = rec;
        pvia::Runtime::instance().set_next_commit_predecessor(
            commit_predecessor);
        vector<u64> payload;
        field_vector_serialize(codeword, payload);
        pvia::Runtime::instance().observe_local_payload(payload);
        pvia::Runtime::instance().consume_pending();
        pvia::Runtime::instance().seal_checkpoint_instance(
            pvia::Phase::ENCODING, 2);
        const pvia::StateId codeword_state =
            pvia::Runtime::instance().import_state(
                "direct_commit_codeword", pvia::Phase::ORACLE, codeword);
        pvia::Runtime::instance().set_next_commit_state_dependency(
            codeword_state);
    }
    pt_cp.end();
    enforce_encoding_stage2_release_gate();
    distributed_MT(codeword, Com,N);
}


void plaintext_commit(vector<F> &data, vector<F> &codeword ,vector<F> &row_data, MT &Com, int k, int N){
    double pt_temp = pt_cp.get_time();
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
    timer com_time;com_time.start();
    
    MPI_Request req;
    //MPI_Alltoall(send_buff.data(),send_buff.size()/N,MPI_UINT64_T,recv_buff.data(),recv_buff.size()/N,MPI_UINT64_T,MPI_COMM_WORLD);
    MPI_Ialltoall(send_buff.data(),send_buff.size()/N,MPI_UINT64_T,recv_buff.data(),recv_buff.size()/N,MPI_UINT64_T,MPI_COMM_WORLD,&req);
    MPI_Wait(&req,MPI_STATUS_IGNORE);
    com_time.end();
    pt_cp.start();
    
    field_vector_deserialize(recv_buff,row_data);
    codeword = row_data;
    codeword.resize(codeword.size()*2,F(0));
    fft(codeword,(int)log2(codeword.size()),false);
    pt_cp.end();
    
    distributed_MT(codeword,Com,N);
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    
    if(rank == 0) printf("          Commit comp time: %lf, Com time: %lf\n",pt_cp.get_time()-pt_temp,com_time.get_time());
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
    
    pvia::StateId fold_input_state = 0;
    if (pvia::Runtime::instance().enabled()) {
        fold_input_state = pvia::Runtime::instance().import_state(
            "fold_input_codeword", pvia::Phase::FOLD, codeword);
    }

    RS_fold(codeword,a);

    if (pvia::Runtime::instance().enabled()) {
        // RS_fold is deterministic from the active codeword and challenge a.
        // Keep one round-level FOLD block and inject faults only after the
        // honest output has been fixed.
        auto& rt = pvia::Runtime::instance();
        std::vector<pvia::OperationRef> fold_predecessors;
        const uint32_t owner = static_cast<uint32_t>(rt.rank());
        auto predecessor = rt.latest_operation_ref(pvia::Phase::FOLD, owner);
        if (predecessor.object_id == 0)
            predecessor = rt.latest_operation_ref(pvia::Phase::ORACLE, owner);
        if (predecessor.object_id != 0) fold_predecessors.push_back(predecessor);
        pvia::RecordId fold_record =
            rt.register_vector_operation(
                pvia::Phase::FOLD, static_cast<uint32_t>(rnd),
                pvia::Obligation::FOLD, codeword, fold_predecessors);
        if (fold_input_state != 0)
            rt.bind_state_dependencies(
                fold_record, std::vector<pvia::StateId>{fold_input_state});
            rt.bind_relation_kernel(
                fold_record, pvia::AuditRelationKernel::FOLD_RS);
        rt.bind_public_field_aux(
            fold_record, pvia::AuditPublicAuxKind::FOLD_CHALLENGE,
            vector<F>{a});
        pvia::Runtime::instance().activate_vector(fold_record, codeword);
        vector<u64> fold_payload;
        field_vector_serialize(codeword, fold_payload);
        pvia::Runtime::instance().observe_local_payload(fold_payload);
        pvia::Runtime::instance().consume_pending();
        pvia::Runtime::instance().seal_checkpoint_instance(
            pvia::Phase::FOLD, static_cast<uint32_t>(rnd));
        pvia::Runtime::instance().import_state(
            "fold_output_codeword", pvia::Phase::FOLD, codeword);
    }

    merkle_tree::merkle_tree_prover::MT_commit_Blake(codeword.data(),Hashes.Base_MT, codeword.size());
    // Distributed MT is not needed her. It will be done in the next sumcheck round to save some synch rounds
    //distributed_MT(codeword,Hashes,N);
    for(int i = 0; i < data.size()/(1ULL<<(rnd+1)); i++){
        data[i] = data[2*i] + a*(data[2*i+1]-data[2*i]);
        beta[i] = beta[2*i] + a*(beta[2*i+1]-beta[2*i]);
    }
        
}


namespace {
struct PcsLeafOpeningEvidence {
    std::array<F,4> leaf{};
    uint32_t field_index = 0;
};
struct PcsReplyLeafEvidence {
    PcsLeafOpeningEvidence first;
    PcsLeafOpeningEvidence second;
};
using PcsReplyLeafRounds = std::vector<std::vector<PcsReplyLeafEvidence>>;

PcsLeafOpeningEvidence make_pcs_leaf_opening(const vector<F>& codeword, uint32_t field_index) {
    PcsLeafOpeningEvidence out;
    out.field_index = field_index;
    if (codeword.size() < 4 || (codeword.size() % 4) != 0 || field_index >= codeword.size()) return out;
    const size_t base = (static_cast<size_t>(field_index) / 4) * 4;
    for (size_t i = 0; i < 4; ++i) out.leaf[i] = codeword[base+i];
    return out;
}

PcsReplyLeafRounds build_pcs_reply_leaf_evidence(const vector<vector<F>>& folded_codewords, vector<vector<u32>> queries) {
    PcsReplyLeafRounds out(folded_codewords.size());
    for (size_t round = 0; round < folded_codewords.size(); ++round) {
        const auto& codeword = folded_codewords[round];
        if (codeword.empty() || (codeword.size() % 4) != 0) return {};
        const uint32_t half = static_cast<uint32_t>(codeword.size()/2);
        out[round].reserve(queries.size());
        for (const auto& query : queries) {
            if (query.size() < 2 || query[1] >= codeword.size() || half == 0) return {};
            const uint32_t first = query[1] < half ? query[1] : query[1]-half;
            const uint32_t second = first + half;
            out[round].push_back({make_pcs_leaf_opening(codeword, first), make_pcs_leaf_opening(codeword, second)});
        }
        for (auto& query : queries) if (query[1] >= half) query[1] -= half;
    }
    return out;
}
} // namespace

// Identical to query algorithm 
void verify_queries(int N,int M,vector<vector<u32>> query_indexes, 
                                 vector<vector<vector<F>>> replies,
                                 vector<vector<vector<F>>> replies_mask,
                                 vector<F> a,
                                 vector<F> b,
                                 MT &Initial_tree,
                                 vector<MT> &Middle_trees,
                                 double &ps,
                                 bool verify = true,
                                 vector<MT>* Mask_trees = nullptr){
    
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
    bool pvia_merkle_ok = true;
    auto verify_merkle_path = [&](vector<vector<_hash>>& tree, int pos, int leaves,
                                  vector<bool>& seen, uint32_t round_marker,
                                  const char* path_label) {
        vector<_hash> proof =
            merkle_tree::merkle_tree_prover::open_tree_blake(tree, pos);
        const bool ok = merkle_tree::merkle_tree_verifier::verify_claim_opt_blake(
            tree, proof.data(), pos, leaves, seen, temp_ps);
        ps += temp_ps;
        temp_ps = 0.0;
        return ok;
    };
    auto verify_reply_pair = [&](vector<vector<_hash>>& tree, vector<F>& reply,
                                 size_t query_pos, vector<bool>& seen,
                                 uint32_t round, const char* path_family,
                                 const char* leaf_family) {
        if (!pvia_reply_leafs_match_tree(tree, query_pos, reply)) return false;
        const size_t total = tree[0].size()*4;
        const size_t half = total/2;
        const size_t p0 = query_pos < half ? query_pos : query_pos-half;
        const size_t p1 = query_pos < half ? query_pos+half : query_pos;
        const int leaves = static_cast<int>(tree[0].size());
        return verify_merkle_path(
                   tree, static_cast<int>(p0/4), leaves, seen,
                   round, path_family) &&
               verify_merkle_path(
                   tree, static_cast<int>(p1/4), leaves, seen,
                   round, path_family);
    };

    vector<vector<vector<bool>>> mask_seen(replies_mask.size());
    if (!replies_mask.empty()) {
        if (!Mask_trees || Mask_trees->size() < replies_mask.size()) {
            pvia_merkle_ok = false;
        }
        else {
            for (size_t r = 0; r < replies_mask.size(); ++r) {
                mask_seen[r].resize(N);
                const size_t leaves = (*Mask_trees)[r].Base_MT.empty() ? 0 :
                    (*Mask_trees)[r].Base_MT[0].size();
                for (int owner = 0; owner < N; ++owner)
                    mask_seen[r][owner].resize(2*leaves, false);
            }
        }
    }

    if (replies.empty() || replies[0].size() != query_indexes.size()) {
        pvia_merkle_ok = false;
    }
    for(size_t i = 0; i < query_indexes.size() && !replies.empty(); i++){
        const int owner = static_cast<int>(query_indexes[i][0]);
        if (owner < 0 || owner >= N) { pvia_merkle_ok = false; continue; }
        pvia_merkle_ok = verify_reply_pair(
            Initial_tree.Base_MT, replies[0][i], query_indexes[i][1],
            visited[owner], 0, "PCS_MERKLE_PATH", "PCS_MERKLE_LEAF") &&
            pvia_merkle_ok;
        if (!replies_mask.empty()) {
            if (!Mask_trees || Mask_trees->empty() ||
                replies_mask[0].size() != query_indexes.size()) {
                pvia_merkle_ok = false;
            } else {
                pvia_merkle_ok = verify_reply_pair(
                    (*Mask_trees)[0].Base_MT, replies_mask[0][i],
                    query_indexes[i][1], mask_seen[0][owner], 0,
                    "PCS_MASK_MERKLE_PATH", "PCS_MASK_MERKLE_LEAF") &&
                    pvia_merkle_ok;
            }
        }
    }
    if(rank == 0) ps += 32.0*(int)(N)/1024.0;

    vector<vector<u32>> temp_queries = query_indexes;
    size_t round_total = static_cast<size_t>(4)*M;
    for(size_t i = 0; i < Middle_trees.size(); i++){
        const size_t next_total = round_total/2;
        for(size_t j = 0; j < temp_queries.size(); j++)
            if(temp_queries[j][1] >= next_total)
                temp_queries[j][1] -= static_cast<u32>(next_total);
        round_total = next_total;
        const size_t main_leaves = Middle_trees[i].Base_MT.empty() ? 0 :
            Middle_trees[i].Base_MT[0].size();
        for(int owner = 0; owner < N; owner++)
            visited[owner].assign(2*main_leaves, false);
        const size_t reply_round = i+1;
        if (reply_round < replies.size() &&
            replies[reply_round].size() != temp_queries.size())
            pvia_merkle_ok = false;
        for(size_t j = 0; j < temp_queries.size(); j++){
            const int owner = static_cast<int>(temp_queries[j][0]);
            if (owner < 0 || owner >= N) { pvia_merkle_ok = false; continue; }
            if (reply_round < replies.size()) {
                pvia_merkle_ok = verify_reply_pair(
                    Middle_trees[i].Base_MT, replies[reply_round][j],
                    temp_queries[j][1], visited[owner],
                    static_cast<uint32_t>(reply_round),
                    "PCS_MERKLE_PATH", "PCS_MERKLE_LEAF") &&
                    pvia_merkle_ok;
            } else if (main_leaves > 0) {
                pvia_merkle_ok = verify_merkle_path(
                    Middle_trees[i].Base_MT,
                    static_cast<int>(temp_queries[j][1]/4),
                    static_cast<int>(main_leaves), visited[owner],
                    static_cast<uint32_t>(reply_round),
                    "PCS_MERKLE_PATH") && pvia_merkle_ok;
            }
            if (reply_round < replies_mask.size()) {
                if (!Mask_trees || Mask_trees->size() <= reply_round ||
                    replies_mask[reply_round].size() != temp_queries.size()) {
                    pvia_merkle_ok = false;
                } else {
                    pvia_merkle_ok = verify_reply_pair(
                        (*Mask_trees)[reply_round].Base_MT,
                        replies_mask[reply_round][j], temp_queries[j][1],
                        mask_seen[reply_round][owner],
                        static_cast<uint32_t>(reply_round),
                        "PCS_MASK_MERKLE_PATH", "PCS_MASK_MERKLE_LEAF") &&
                        pvia_merkle_ok;
                }
            }
        }
        if(rank == 0) ps += 32.0*(int)(N)/1024.0;
    }
    int local_merkle_ok = pvia_merkle_ok ? 1 : 0;
    int global_merkle_ok = 0;
    MPI_Allreduce(&local_merkle_ok, &global_merkle_ok, 1, MPI_INT, MPI_MIN, MPI_COMM_WORLD);
    if (!global_merkle_ok) {
        if (rank == 0) printf("[PVIA][PublicDirect] WITHHOLD pcs_merkle_path before opening fold checks\n");
        if (pvia::Runtime::instance().enabled())
            pvia::Runtime::instance().handle_global_failure("pcs_merkle_path", pvia::Phase::OPENING, 0);
        std::exit(15);
    }
    F two_inv = F(2).inv();
    auto pvia_query_fault = [&](int round, int query, int slot, F expected, F actual) {
        if (pvia::Runtime::instance().enabled() && rank == 0) {
            const uint32_t owner = query_indexes[query][0];
            const uint64_t object_id =
                0x8000000000000000ULL |
                (static_cast<uint64_t>(round) << 32) |
                static_cast<uint32_t>(query);
            pvia::Runtime::instance().record_public_vector_violation(
                pvia::Phase::OPENING, static_cast<uint32_t>(round),
                pvia::Obligation::OPEN, owner, object_id,
                vector<F>{expected}, vector<F>{actual},
                vector<u64>{static_cast<u64>(owner),
                            static_cast<u64>(query),
                            static_cast<u64>(query_indexes[query][1]),
                            static_cast<u64>(row_size),
                            static_cast<u64>(round),
                            static_cast<u64>(slot)});
            pvia::Runtime::instance().handle_global_failure(
                "pcs_query_fold", pvia::Phase::OPENING,
                static_cast<uint32_t>(round));
        }
    };
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
                    pvia_query_fault(i, j, 0, aggr1 + b[i]*aggr2, replies[i+1][j][0]);
                    //return;
                }
                if(verify && (query_indexes[j][1] > (row_size/(1<<(i+2))) && (replies[i+1][j][1] != aggr1 + b[i]*aggr2))){
                    printf("! error %d\n",j);
                    pvia_query_fault(i, j, 1, aggr1 + b[i]*aggr2, replies[i+1][j][1]);
                    //return;
                }
            }else{
                if(verify && (query_indexes[j][1] < (row_size/(1<<(i+2))) && (replies[i+1][j][0] != aggr1 ))){
                    printf("@ error %d,%d\n",i,j);
                    pvia_query_fault(i, j, 0, aggr1, replies[i+1][j][0]);
                    //return;
                }
                if(verify && (query_indexes[j][1] > (row_size/(1<<(i+2))) && (replies[i+1][j][1] != aggr1 ))){
                    printf("> error %d,%d\n",i,j);
                    pvia_query_fault(i, j, 1, aggr1, replies[i+1][j][1]);
                    //return;
                }
            }
            

        }
    }
    vt.end();
        
    //printf("%lf\n",ps);

}


bool verify_queries_local(int N,int M,vector<vector<u32>> query_indexes, 
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
    bool pvia_merkle_ok = true;
    auto verify_merkle_path = [&](vector<vector<_hash>>& tree, vector<_hash>& proof,
                                  int pos, int leaves, vector<bool>& seen,
                                  uint32_t round_marker) {
        return merkle_tree::merkle_tree_verifier::verify_claim_opt_blake(
            tree, proof.data(), pos, leaves, seen, temp_ps);
    };
    auto verify_local_reply_pair = [&](vector<vector<_hash>>& tree, vector<F>& reply,
                                       size_t query_pos, vector<bool>& seen,
                                       uint32_t reply_round) {
        if (!pvia_reply_leafs_match_tree(tree, query_pos, reply)) return false;
        const size_t total = tree[0].size()*4;
        const size_t half = total/2;
        const size_t p0 = query_pos < half ? query_pos : query_pos-half;
        const size_t p1 = query_pos < half ? query_pos+half : query_pos;
        vector<_hash> proof0 = merkle_tree::merkle_tree_prover::open_tree_blake(tree, p0/4);
        vector<_hash> proof1 = merkle_tree::merkle_tree_prover::open_tree_blake(tree, p1/4);
        const int leaves = static_cast<int>(tree[0].size());
        return verify_merkle_path(tree, proof0, static_cast<int>(p0/4), leaves, seen, reply_round) &&
               verify_merkle_path(tree, proof1, static_cast<int>(p1/4), leaves, seen, reply_round);
    };

    vector<vector<bool>> visited(N);
    vector<vector<u32>> temp_queries = query_indexes;
    for(size_t i = 0; i < Middle_trees.size(); i++){
        const size_t next_total = static_cast<size_t>(4)*M/2;
        for(size_t j = 0; j < temp_queries.size(); j++)
            if(temp_queries[j][1] >= next_total)
                temp_queries[j][1] -= static_cast<u32>(next_total);
        M /= 2;
        const size_t reply_round = i+1;
        if (reply_round < replies.size() && replies[reply_round].size() != temp_queries.size())
            pvia_merkle_ok = false;
        for(int owner = 0; owner < N; ++owner) {
            const size_t leaves = (i < Middle_trees.size() && owner < static_cast<int>(Middle_trees[i].size()) &&
                                   !Middle_trees[i][owner].Base_MT.empty())
                ? Middle_trees[i][owner].Base_MT[0].size() : 0;
            visited[owner].assign(2*leaves, false);
        }
        for(size_t j = 0; j < temp_queries.size(); j++){
            const int owner = static_cast<int>(temp_queries[j][0]);
            if (owner < 0 || owner >= N || owner >= static_cast<int>(Middle_trees[i].size())) {
                pvia_merkle_ok = false;
                continue;
            }
            auto& tree = Middle_trees[i][owner].Base_MT;
            if (tree.empty() || tree[0].empty()) {
                pvia_merkle_ok = false;
                continue;
            }
            if (reply_round < replies.size()) {
                pvia_merkle_ok = verify_local_reply_pair(
                    tree, replies[reply_round][j], temp_queries[j][1],
                    visited[owner], static_cast<uint32_t>(reply_round)) && pvia_merkle_ok;
            } else {
                vector<_hash> proof = merkle_tree::merkle_tree_prover::open_tree_blake(
                    tree, temp_queries[j][1]/4);
                pvia_merkle_ok = verify_merkle_path(
                    tree, proof, temp_queries[j][1]/4, static_cast<int>(tree[0].size()),
                    visited[owner], static_cast<uint32_t>(reply_round)) && pvia_merkle_ok;
                ps += temp_ps;
                temp_ps = 0.0;
            }
        }
        ps += 32.0*(int)(N)/1024.0;
    }
    if (!pvia_merkle_ok) return false;
    F two_inv = F(2).inv();
    auto pvia_local_query_fault = [&](int round, int query, int slot, F expected, F actual) {
        if (pvia::Runtime::instance().enabled() && rank == 0) {
            const uint32_t owner = query_indexes[query][0];
            const uint64_t object_id = 0xC000000000000000ULL |
                (static_cast<uint64_t>(round) << 32) |
                static_cast<uint32_t>(query);
            pvia::Runtime::instance().record_public_vector_violation(
                pvia::Phase::OPENING, static_cast<uint32_t>(round), pvia::Obligation::OPEN,
                owner, object_id, vector<F>{expected}, vector<F>{actual},
                vector<u64>{static_cast<u64>(owner),
                            static_cast<u64>(query),
                            static_cast<u64>(query_indexes[query][1]),
                            static_cast<u64>(row_size),
                            static_cast<u64>(round),
                            static_cast<u64>(slot)});
            pvia::Runtime::instance().handle_global_failure(
                "pcs_local_query_fold", pvia::Phase::OPENING, static_cast<uint32_t>(round));
        }
    };
    
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
                pvia_local_query_fault(i, j, 0, aggr1, replies[i+1][j][0]);
            }
            if(verify && (query_indexes[j][1] > (row_size/(1<<(i+2))) && (replies[i+1][j][1] != aggr1 ))){
                printf("> error %d,%d\n",i,j);
                pvia_local_query_fault(i, j, 1, aggr1, replies[i+1][j][1]);
            }
            
        }
    }
    vt.end();
        
    //printf("%lf\n",ps);

    return true;
}

bool local_open(vector<vector<F>> &codeword, vector<vector<F>> &row_data, vector<F> &v1, vector<F> &v2,vector<F> &old_v2, vector<vector<u32>> &query_index,
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
            replies[i].push_back(
                pvia_build_merkle_reply(
                    folded_codewords[i][query_index[j][0]], query_index[j][1]));
            }
            for(int j = 0; j < query_index.size(); j++){
                if(query_index[j][1] >= folded_codewords[i][query_index[j][0]].size()/2){
                    query_index[j][1] -= folded_codewords[i][query_index[j][0]].size()/2;
                }
            }
        }

    if (!verify_queries_local(N,folded_codewords[0][0].size()/4, initial_query_index, 
                                 replies,
                                 challenges,
                                 eval_MT,
                                 ps,
                                 verify)) return false;



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
            
        
    return true;
}


bool recv_batch_PC_data(vector<vector<vector<F>>> &codeword, vector<vector<vector<F>>> &row_data, vector<vector<vector<u32>>> &query_index, vector<int> codeword_size, vector<int> size, vector<int> l, int N){
    bool transfer_ok = true;
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
        std::array<u64, pvia::META_WORDS> remote_meta{};
        if (pvia::Runtime::instance().enabled()) {
            MPI_Recv(remote_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                     i, pvia::META_TAG, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        }
        MPI_Wait(&stat[i-1],MPI_STATUS_IGNORE);
        bool sender_ok = true;
        if (pvia::Runtime::instance().enabled()) {
            sender_ok = pvia::Runtime::instance().strict_remote_transfer_valid(i, remote_meta, buff64[i-1]);
            pvia::Runtime::instance().observe_remote_meta(i, remote_meta, buff64[i-1]);
            if (!sender_ok) transfer_ok = false;
        }
        if (!sender_ok) continue;
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
    return transfer_ok;
}

bool recv_PC_data(vector<vector<F>> &codeword, vector<vector<F>> &row_data, vector<vector<u32>> &query_index, int codeword_size, int size, int l, int N){
    bool transfer_ok = true;
    vector<vector<u64>> buff64(N-1);
    for(int i = 0; i < N-1;i++) buff64[i].resize(2*(codeword_size+size)+l+1); 
    vector<u64> code_buff(2*codeword_size),row_buff(2*size);
    vector<MPI_Request> stat(N-1);
    for(int i = 1; i < N; i++){
        
        MPI_Irecv(buff64[i-1].data(),buff64[i-1].size(),MPI_UINT64_T, i,0,MPI_COMM_WORLD,&stat[i-1]);
    }
    for(int i = 1; i < N; i++){
        std::array<u64, pvia::META_WORDS> remote_meta{};
        if (pvia::Runtime::instance().enabled()) {
            MPI_Recv(remote_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                     i, pvia::META_TAG, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        }
        MPI_Wait(&stat[i-1],MPI_STATUS_IGNORE);
        bool sender_ok = true;
        if (pvia::Runtime::instance().enabled()) {
            sender_ok = pvia::Runtime::instance().strict_remote_transfer_valid(i, remote_meta, buff64[i-1]);
            pvia::Runtime::instance().observe_remote_meta(i, remote_meta, buff64[i-1]);
            if (!sender_ok) transfer_ok = false;
        }
        if (!sender_ok) continue;
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
    return transfer_ok;
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
        if (pvia::Runtime::instance().enabled()) {
            auto meta = pvia::Runtime::instance().make_direct_meta(
                pvia::Phase::OPENING, 0, pvia::Obligation::SEND,
                pvia::Runtime::instance().allocate_object_id(), buff_64, false);
            pvia::Runtime::instance().seal_transfer_meta(meta, buff_64);
            pvia::Runtime::instance().observe_direct_local(meta, buff_64);
            MPI_Send(meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                     0, pvia::META_TAG, MPI_COMM_WORLD);
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
        cm += 8*buff_64.size()/1024.0;
        if (pvia::Runtime::instance().enabled()) {
            auto meta = pvia::Runtime::instance().make_direct_meta(
                pvia::Phase::OPENING, 0, pvia::Obligation::SEND,
                pvia::Runtime::instance().allocate_object_id(), buff_64, false);
            pvia::Runtime::instance().seal_transfer_meta(meta, buff_64);
            pvia::Runtime::instance().observe_direct_local(meta, buff_64);
            MPI_Send(meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                     0, pvia::META_TAG, MPI_COMM_WORLD);
        }
        MPI_Isend(buff_64.data(),buff_64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&stat);
        MPI_Wait(&stat, MPI_STATUS_IGNORE);
    }
    
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
            y_mask[i] = F_ip(mask_data[i],beta1,beta2,k,_k,N,
                PVIA_SCALAR_CTX_PCS_MASK_BASE + static_cast<uint32_t>(i));
            aggr_challenges[i] = hash_to_field({y_mask[i]});
            //aggr_challenges[i] = F(0);
        }else{
            
            if(rounds-i-PC_offset <= 0) {
                rounds = i;
                eval_MT.resize(rounds);
                challenges.resize(rounds);
                aggr_challenges.resize(rounds);
                break;
            }
            
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

        // PVIA: bind the PCS local round polynomial before it is consumed
        // by the coded aggregation layer.  This separates a bad local
        // derivation from a later aggregation/publication deviation.
        pvia::RecordId pvia_record = 0;
        if (pvia::Runtime::instance().enabled()) {
            auto& rt = pvia::Runtime::instance();
            vector<F> pvia_source_state = beta1;
            pvia_source_state.insert(
                pvia_source_state.end(), row_data.begin(), row_data.end());
            if (i < masking_rounds) {
                pvia_source_state.insert(
                    pvia_source_state.end(),
                    mask_data[i].begin(), mask_data[i].end());
            }
            const pvia::StateId source_state = rt.import_state(
                "pcs_open_round_input", pvia::Phase::PCS,
                pvia_source_state);
            std::vector<pvia::OperationRef> predecessors;
            const auto predecessor = rt.previous_round_operation_ref(
                pvia::Phase::PCS, static_cast<uint32_t>(i),
                pvia::Obligation::PUBLISH);
            if (predecessor.object_id != 0) predecessors.push_back(predecessor);
            pvia_record = rt.register_quadratic_operation(
                pvia::Phase::PCS, i, pvia::Obligation::DERIVE, H, predecessors);
            rt.bind_state_dependencies(
                pvia_record, std::vector<pvia::StateId>{source_state});
            rt.bind_relation_kernel(
                pvia_record, pvia::AuditRelationKernel::PCS_OPEN_ROUND);
            vector<F> pvia_round_aux = {
                y, aggr_challenges[i], y_mask[i]};
            if (i > 0) pvia_round_aux.push_back(challenges[i-1]);
            rt.bind_public_field_aux(
                pvia_record, pvia::AuditPublicAuxKind::SUMCHECK_CHALLENGE,
                pvia_round_aux);
            pvia::Runtime::instance().activate_quadratic(pvia_record, H);
        }
        
        H = aggregate_quadratic_poly(
            H, beta2, k, _k, N, "pcs_open_round_release");
        if(verify && H.eval(0) + H.eval(1) != y + aggr_challenges[i]*y_mask[i]){
            printf("> Error in open round %d\n",i);
            if (pvia::Runtime::instance().enabled()) {
                pvia::Runtime::instance().handle_global_failure(
                    "pcs_open_round", pvia::Phase::PCS,
                    static_cast<uint32_t>(i));
            }
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
    

    //if(PC_offset == 0){
        // Generate opening proofs 
        vector<vector<u32>> initial_index, query_index = get_indexes(l,N,folded_codewords[0].size(),rank);
        initial_index = query_index;
        vector<vector<vector<F>>> replies(rounds),replies_mask(masking_rounds); 
        for(int i = 0; i < rounds; i++){
            for(int j = 0; j < query_index.size(); j++){
                replies[i].push_back(
                    pvia_build_merkle_reply(folded_codewords[i], query_index[j][1]));
                if(i < masking_rounds){
                    replies_mask[i].push_back(
                        pvia_build_merkle_reply(mask_codeword[i], query_index[j][1]));
                }
            }
            for(int j = 0; j < query_index.size(); j++){
                if(query_index[j][1] >= folded_codewords[i].size()/2){
                    query_index[j][1] -= folded_codewords[i].size()/2;
                }
            }
        }

        verify_queries(N,folded_codewords[0].size()/4,  initial_index, replies, replies_mask,
                                    challenges, aggr_challenges, Com, eval_MT, ps, verify, &Mask_Com);

        // Send the final codeword to P0
        
    if(PC_offset>0){
        com_rounds += 1;
        //vector<vector<u32>> initial_index, query_index = get_indexes(l,N,2*rate*(1<<rounds),rank);
        
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
            vector<F> beta2_old;
            //local_open(all_codewords,all_row_data,beta1,beta2,beta2_old,query_index,y,l,k,N,ps,true,verify);
        }

    }else{
        com_rounds++;
        if(rank != 0){
            vector<u64> buff;
            field_vector_serialize(codeword,buff);
            cm += 8*buff.size()/1024.0;
            if (pvia::Runtime::instance().enabled()) {
                auto meta = pvia::Runtime::instance().make_direct_meta(
                    pvia::Phase::OPENING, static_cast<uint32_t>(rounds),
                    pvia::Obligation::SEND,
                    pvia::Runtime::instance().allocate_object_id(), buff, false);
                pvia::Runtime::instance().seal_transfer_meta(meta, buff);
                pvia::Runtime::instance().observe_direct_local(meta, buff);
                MPI_Send(meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                         0, pvia::META_TAG, MPI_COMM_WORLD);
            }
            MPI_Request req;
            MPI_Isend(buff.data(),buff.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,&req);
            MPI_Wait(&req,MPI_STATUS_IGNORE);
            //MPI_Send(buff.data(),buff.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD);
        }else{
            vt.start();
            
            vector<vector<F>> final_codeword(N);
            final_codeword[0] = codeword;
            vector<u64> buff(2*codeword.size());
            vector<vector<u64>> recv_data(N);
            vector<MPI_Request> req(N);
            for(int i = 1; i < N; i++){
                recv_data[i].resize(2*codeword.size());
                MPI_Irecv(recv_data[i].data(),recv_data[i].size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,&req[i]);
                //MPI_Recv(buff.data(),buff.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            }
            for(int i = 1; i < N; i++){
                std::array<u64, pvia::META_WORDS> remote_meta{};
                if (pvia::Runtime::instance().enabled()) {
                    MPI_Recv(remote_meta.data(), pvia::META_WORDS, MPI_UINT64_T,
                             i, pvia::META_TAG, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
                }
                MPI_Wait(&req[i],MPI_STATUS_IGNORE);
                if (pvia::Runtime::instance().enabled()) {
                    pvia::Runtime::instance().observe_remote_meta(i, remote_meta, recv_data[i]);
                }
                field_vector_deserialize(recv_data[i],codeword);
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
                if (pvia::Runtime::instance().enabled()) {
                    pvia::Runtime::instance().handle_global_failure(
                        "pcs_final_codeword_check", pvia::Phase::OPENING,
                        static_cast<uint32_t>(rounds));
                }
            }else{
                //printf("PC Verification Success\n");
            }
            vt.end();
            
        }
    }
    

}



void open_plaintext(vector<F> &codeword, vector<F> &row_data,
                    vector<F> &v1, vector<F> &v2, MT &Com, F y, int l, int k, int N, double &ps, bool secret_shared, bool verify){

    pt_cp.start();
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    int local_merkle_ok = 1;
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


        query_index = get_indexes(l,N,folded_codewords[0].size(),rank);
        initial_index = query_index;
        vector<vector<vector<F>>> replies(rounds); 
        for(int i = 0; i < rounds; i++){
            for(int j = 0; j < query_index.size(); j++){
                replies[i].push_back(
                    pvia_build_merkle_reply(folded_codewords[i], query_index[j][1]));
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
            const bool transfer_ok = recv_PC_data(all_codewords,all_row_data,query_index,codeword.size(),row_data.size()/(1<<(rounds)),l,N);
            
            //all_queries.insert(all_queries.begin(),query_index);
            local_merkle_ok = transfer_ok && local_open(all_codewords,all_row_data,v1,v2,old_v2,query_index,y,l,k,N,ps,secret_shared,verify) ? 1 : 0;
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
    
    
    if (PC_offset) {
        MPI_Bcast(&local_merkle_ok, 1, MPI_INT, 0, MPI_COMM_WORLD);
        if (!local_merkle_ok) {
            if (rank == 0) printf("[PVIA][PublicDirect] WITHHOLD pcs_local_merkle_path before opening fold checks\n");
            if (pvia::Runtime::instance().enabled())
                pvia::Runtime::instance().handle_global_failure("pcs_local_merkle_path", pvia::Phase::OPENING, 0);
            std::exit(15);
        }
    }

}


void batch_open(vector<vector<F>> &codeword, vector<vector<F>> &row_data,
                    vector<vector<F>> &v1, vector<vector<F>> &v2, vector<MT> &Com, vector<F> y, vector<int> l, vector<int> k, int N, double &ps, vector<bool> secret_shared, vector<bool> verify){
    
    pt_cp.start();
    int batch_size = codeword.size();
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    int batch_local_merkle_ok = 1;
    
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

        // PVIA: treat all active local PCS replies in this round as one
        // accountability block, matching the batched aggregation boundary.
        if (pvia::Runtime::instance().enabled()) {
            vector<F> expected_block;
            for(int j = 0; j < batch_size; j++) {
                if(rounds[j] > i) {
                    expected_block.push_back(H[j].a);
                    expected_block.push_back(H[j].b);
                    expected_block.push_back(H[j].c);
                }
            }
            auto& rt = pvia::Runtime::instance();
            vector<F> pvia_source_state;
            for(int j = 0; j < batch_size; j++) {
                if(rounds[j] > i) {
                    pvia_source_state.insert(
                        pvia_source_state.end(), v1[j].begin(), v1[j].end());
                    pvia_source_state.insert(
                        pvia_source_state.end(),
                        row_data[j].begin(), row_data[j].end());
                }
            }
            const pvia::StateId source_state = rt.import_state(
                "pcs_batch_round_input", pvia::Phase::PCS, pvia_source_state);
            std::vector<pvia::OperationRef> predecessors;
            const auto predecessor = rt.previous_round_operation_ref(
                pvia::Phase::PCS, static_cast<uint32_t>(i),
                pvia::Obligation::PUBLISH);
            if (predecessor.object_id != 0) predecessors.push_back(predecessor);
            pvia::RecordId batch_record =
                rt.register_vector_operation(
                    pvia::Phase::PCS, i,
                    pvia::Obligation::DERIVE, expected_block, predecessors);
            rt.bind_state_dependencies(
                batch_record, std::vector<pvia::StateId>{source_state});
            rt.bind_relation_kernel(
                batch_record, pvia::AuditRelationKernel::PCS_BATCH_OPEN_ROUND);
            vector<F> pvia_round_aux;
            pvia_round_aux.push_back(F(batch_size));
            for (int j = 0; j < batch_size; ++j) {
                if (rounds[j] > i) {
                    pvia_round_aux.push_back(F(j));
                    pvia_round_aux.push_back(y[j]);
                    pvia_round_aux.push_back(F(rounds[j]));
                }
            }
            if (i > 0) pvia_round_aux.push_back(challenges[i-1]);
            rt.bind_public_field_aux(
                batch_record, pvia::AuditPublicAuxKind::SUMCHECK_CHALLENGE,
                pvia_round_aux);


            vector<F> actual_block;
            for(int j = 0; j < batch_size; j++) {
                if(rounds[j] > i) {
                    actual_block.push_back(H[j].a);
                    actual_block.push_back(H[j].b);
                    actual_block.push_back(H[j].c);
                }
            }
            pvia::Runtime::instance().activate_vector(batch_record, actual_block);
        }
        H = batch_aggregate(
            H, v2, secret_shared, rounds, k, i, N,
            "pcs_batch_open_round_release");
        //printf("%d (%lld,%lld),(%lld,%lld),(%lld,%lld)\n",i,H[1].a.real,H[1].a.img,H[1].b.real,H[1].b.img,H[1].c.real,H[1].c.img);
        pt_cp.start();
        for(int j = 0; j < batch_size; j++){
            if(rounds[j] > i){
                if(H[j].eval(0) + H[j].eval(1) != y[j] && verify[j]){
                    printf("Error in open round %d,%d, (%lld,%lld)\n",i,rank,(H[j].eval(0) + H[j].eval(1)).real,(H[j].eval(0) + H[j].eval(1)).img);
                    if (pvia::Runtime::instance().enabled()) {
                        pvia::Runtime::instance().handle_global_failure(
                            "pcs_batch_open_round", pvia::Phase::PCS,
                            static_cast<uint32_t>(i));
                    }
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
                replies[h][i].push_back(
                    pvia_build_merkle_reply(
                        folded_codewords[h][i], query_index[h][j][1]));
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
            const bool transfer_ok = recv_batch_PC_data(all_codewords,all_row_data,query_index,codeword_size,row_data_size,l,N);
            if (!transfer_ok) {
                batch_local_merkle_ok = 0;
            } else {
                for(int i = 0; i < batch_size; i++){
                    all_codewords[i][0] = codeword[i];
                    all_row_data[i][0].resize(row_data_size[i]);
                    for(int j = 0; j  < row_data_size[i]; j++){
                        all_row_data[i][0][j] = row_data[i][j];
                    }
                }
                //all_queries.insert(all_queries.begin(),query_index);
                for(int i = 0; i < batch_size; i++){ 
                    if (!local_open(all_codewords[i],all_row_data[i],v1[i],v2[i],old_v2[i],query_index[i],y[i],l[i],k[i],N,ps,secret_shared[i],verify[i])) {
                        batch_local_merkle_ok = 0;
                        break;
                    }
                }
            }
        }
        //open_plaintext(codeword[0],row_data[0],v1[0],v2[0],Com[0],y[0],l[0],k[0],N,ps,secret_shared[0],verify[0]);
           
    }    
 
    MPI_Bcast(&batch_local_merkle_ok, 1, MPI_INT, 0, MPI_COMM_WORLD);
    if (!batch_local_merkle_ok) {
        if (rank == 0) printf("[PVIA][PublicDirect] WITHHOLD pcs_batch_local_merkle_path before opening fold checks\n");
        if (pvia::Runtime::instance().enabled())
            pvia::Runtime::instance().handle_global_failure("pcs_batch_local_merkle_path", pvia::Phase::OPENING, 0);
        std::exit(15);
    }

}

//void open_index(vector<F> &row_data, vector<F> &codeword, MT &index_Com, int rate){
//    int 
//}