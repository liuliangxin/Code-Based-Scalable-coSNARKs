#include "Fiat_Shamir.h"


F initial_challenge = F(0);
F prev_challenge = F(0);


F hash_F(F x, F y){
    _hash H;
    vector<F> element(2);
    uint8_t data[64];
    element[0] = x;
    element[1] = 0;
    memcpy(data, element.data(), 2 * sizeof(F));
    element[0] = y;
    element[1] = 0;
    //hashes[0][i].resize(32);
    memcpy(data + 32, element.data(), 2 * sizeof(F));
    blake3_hash(data, H.arr);
    u64 real = 0,img = (0);
    for(int i = 0; i < 8; i++){
        real += (1ULL<<(7*i))*H.arr[i];
        img += (1ULL<<(7*i))*H.arr[i+8];
    }
    F ret; ret.real = real;ret.img = img;
    return ret;
}

F hash_to_field(vector<F> elements){
    for(int i = 0; i < elements.size(); i++){
        prev_challenge = hash_F(prev_challenge,elements[i]);
    }
    return prev_challenge;
}


vector<vector<u32>> get_indexes(int l, int N, int M, int pos){
    vector<vector<u32>> idx(l);
    vector<vector<u32>> r;
    for(int i = 0; i < l; i++){
        prev_challenge = hash_F(prev_challenge,prev_challenge);
        idx[i].resize(2);
        idx[i][0] = prev_challenge.real%N;
        idx[i][1] = prev_challenge.img%M;
    }
    
    if(pos == -1){
        return idx;
    }
    for(int i = 0 ; i <idx.size() ; i++){
        if(idx[i][0] == pos){
            r.push_back(idx[i]);
        }
    }
    return r;
}
