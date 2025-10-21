#include "MPI_utils.hpp"

extern vector<vector<pair<int,int>>> A,B,C;
// Transposed R1CS matrixes
extern vector<vector<pair<int,int>>> tA,tB,tC;
extern vector<vector<pair<int,int>>> pA,pB,pC;
extern int logm,logn;
extern vector<int> real_idx_dim;


F F_ip(vector<F> &data, vector<F> &v1, vector<F> &v2, int k, int _k, int N){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    F y = F(0),sum = F(0);
    
    for(int i = 0; i < data.size(); i++){
        y += data[i]*v1[i];
    }
    vector<u64> f_element(2);
        
    if(rank == 0){
        vector<F> Y(N);Y[0] = y;
        for(int i = 1; i < N; i++){
            MPI_Recv(f_element.data(),2,MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            Y[i].real = f_element[0];
            Y[i].img = f_element[1];
        }
        fft(Y,(int)log2(Y.size()),true);
        Y.resize(_k);
        fft(Y,(int)log2(Y.size()),false);
        
        for(int i = 0; i < v2.size(); i++){
            sum += v2[i]*Y[i];
        }
        f_element[0] = sum.real;
        f_element[1] = sum.img;
        for(int i = 1; i < N; i++){
            MPI_Send(f_element.data(), 2,MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        }

    }else{
        f_element[0] = y.real;
        f_element[1] = y.img;
        MPI_Send(f_element.data(),2,MPI_UINT64_T,0,0,MPI_COMM_WORLD);
        MPI_Recv(f_element.data(),2,MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        sum.real = f_element[0];
        sum.img = f_element[1];
    }
    return sum;
}

F F_ip_prod(vector<F> &data1, vector<F> &data2, vector<F> &v1, vector<F> &v2, int k, int _k, int N){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    F y = F(0),sum = F(0);
    
    for(int i = 0; i < data1.size(); i++){
        y += data1[i]*data2[i]*v1[i];
    }
    vector<u64> f_element(2);
        
    if(rank == 0){
        vector<F> Y(N);Y[0] = y;
        for(int i = 1; i < N; i++){
            MPI_Recv(f_element.data(),2,MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            Y[i].real = f_element[0];
            Y[i].img = f_element[1];
        }
        fft(Y,(int)log2(Y.size()),true);
        F omega = getRootOfUnity(1+(int)log2(N)).inv();
        F mul = F(1);
        for(int i = 0; i < Y.size(); i++){
            Y[i] = mul*Y[i];
            mul = mul*omega;
        }
        fft(Y,(int)log2(Y.size()),false);
        
        for(int i = 0; i < v2.size(); i++){
            sum += v2[i]*Y[N*i/_k];
        }
        f_element[0] = sum.real;
        f_element[1] = sum.img;
        for(int i = 1; i < N; i++){
            MPI_Send(f_element.data(), 2,MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        }

    }else{
        f_element[0] = y.real;
        f_element[1] = y.img;
        MPI_Send(f_element.data(),2,MPI_UINT64_T,0,0,MPI_COMM_WORLD);
        MPI_Recv(f_element.data(),2,MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        sum.real = f_element[0];
        sum.img = f_element[1];
    }
    return sum;
}

quadratic_poly aggregate_quadratic_poly(quadratic_poly H, int k, int _k, int N){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    F a = F(0),b = F(0),c = F(0);
        
    vector<F> coef; coef.push_back(H.a);coef.push_back(H.b);coef.push_back(H.c);
    vector<u64> coef_u;
    
    field_vector_serialize(coef,coef_u);
    if(rank == 0){
        vector<F> _a(N),_b(N),_c(N);
        _a[0] = coef[0];_b[0] = coef[1];_c[0] = coef[2]; 
        for(int i = 1; i < N; i++){
            MPI_Recv(coef_u.data(),6,MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            field_vector_deserialize(coef_u,coef);
            _a[i] = coef[0];_b[i] = coef[1];_c[i] = coef[2]; 
        }
        fft(_a,(int)log2(_a.size()),true);
        fft(_b,(int)log2(_a.size()),true);
        fft(_c,(int)log2(_a.size()),true);
        F omega = getRootOfUnity(1+(int)log2(N)).inv();
        F mul = F(1);
        for(int i = 0; i < _a.size(); i++){
            _a[i] = mul*_a[i];
            _b[i] = mul*_b[i];
            _c[i] = mul*_c[i];
            mul = mul*omega;
        }
        fft(_a,(int)log2(_a.size()),false);
        fft(_b,(int)log2(_a.size()),false);
        fft(_c,(int)log2(_a.size()),false);
        
        for(int j = 0; j < k; j++){
            a += _a[N*j/_k];
            b += _b[N*j/_k];
            c += _c[N*j/_k];
        }
        coef[0] = a;coef[1] = b;coef[2] = c;
        field_vector_serialize(coef,coef_u);
        for(int i = 1; i < N; i++){
            MPI_Send(coef_u.data(),6,MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        }        
    }else{
        MPI_Send(coef_u.data(),6,MPI_UINT64_T,0,0,MPI_COMM_WORLD);
        MPI_Recv(coef_u.data(),6,MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        field_vector_deserialize(coef_u,coef);
        a = coef[0];b = coef[1];c = coef[2]; 
    }

    H = quadratic_poly(a,b,c);
    return H;
}

quadratic_poly aggregate_quadratic_poly(quadratic_poly H, vector<F> &v, int k, int _k, int N){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    F a = F(0),b = F(0),c = F(0);
        
    vector<F> coef; coef.push_back(H.a);coef.push_back(H.b);coef.push_back(H.c);
    vector<u64> coef_u;
    
    field_vector_serialize(coef,coef_u);
    if(rank == 0){
        vector<F> _a(N),_b(N),_c(N);
        _a[0] = coef[0];_b[0] = coef[1];_c[0] = coef[2]; 
        for(int i = 1; i < N; i++){
            MPI_Recv(coef_u.data(),6,MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            field_vector_deserialize(coef_u,coef);
            _a[i] = coef[0];_b[i] = coef[1];_c[i] = coef[2]; 
        }
        fft(_a,(int)log2(_a.size()),true);
        fft(_b,(int)log2(_a.size()),true);
        fft(_c,(int)log2(_a.size()),true);
        _a.resize(_k);fft(_a,(int)log2(_a.size()),false);
        _b.resize(_k);fft(_b,(int)log2(_a.size()),false);
        _c.resize(_k);fft(_c,(int)log2(_a.size()),false);
        
        for(int j = 0; j < _k; j++){
            a += v[j]*_a[j];
            b += v[j]*_b[j];
            c += v[j]*_c[j];
        }
        coef[0] = a;coef[1] = b;coef[2] = c;
        field_vector_serialize(coef,coef_u);
        for(int i = 1; i < N; i++){
            MPI_Send(coef_u.data(),6,MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        }        
    }else{
        MPI_Send(coef_u.data(),6,MPI_UINT64_T,0,0,MPI_COMM_WORLD);
        MPI_Recv(coef_u.data(),6,MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        field_vector_deserialize(coef_u,coef);
        a = coef[0];b = coef[1];c = coef[2]; 
    }

    H = quadratic_poly(a,b,c);
    return H;
}


vector<F> zero_check_sumcheck_local(vector<F> final_v1, vector<F> final_v2, 
                                    vector<F> final_v3, vector<F> h1, 
                                    vector<F> h2, vector<F> &beta1, vector<F> &beta2,
                                    F b, F y, int k, int _k, int N){
    
    
    fft(final_v1,(int)log2(final_v1.size()),true);
    fft(final_v2,(int)log2(final_v2.size()),true);
    fft(final_v3,(int)log2(final_v3.size()),true);
    fft(h1,(int)log2(h1.size()),true);
    fft(h2,(int)log2(h2.size()),true);
    
    F omega = getRootOfUnity(1+(int)log2(N));
    omega = omega.inv();
    F mul = F(1);
    for(int i = 0; i < final_v1.size(); i++){
        final_v1[i] = mul*final_v1[i];
        final_v2[i] = mul*final_v2[i];
        final_v3[i] = mul*final_v3[i];
        h1[i] = mul*h1[i];
        h2[i] = mul*h2[i];
        mul = mul*omega;
    }

    fft(final_v1,(int)log2(final_v1.size()),false);
    fft(final_v2,(int)log2(final_v2.size()),false);
    fft(final_v3,(int)log2(final_v3.size()),false);
    fft(h1,(int)log2(h1.size()),false);
    fft(h2,(int)log2(h2.size()),false);
    

    vector<F> v1(k),v2(k),v3(k);
    vector<F> r1(k),r2(k);
    
    for(int i = 0; i < k; i++){
        v1[i] = final_v1[N*i/_k];
        v2[i] = final_v2[N*i/_k];
        v3[i] = final_v3[N*i/_k];
        r1[i] = h1[N*i/_k];
        r2[i] = h2[N*i/_k];
    }
    for(int i = 0; i < k; i++){
        beta2[i] = beta2[i]*beta1[0];
    }
    int rounds = (int)log2(k);
    vector<F> challenges(rounds);
    for(int i = 0; i < rounds; i++){
        quadratic_poly p = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
        quadratic_poly p_r = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
        linear_poly _p = linear_poly(F_ZERO,F_ZERO);
        cubic_poly poly = cubic_poly(F_ZERO,F_ZERO,F_ZERO,F_ZERO);
        linear_poly l1,l2;
        for(int j = 0; j < v1.size()/(1<<(i+1)); j++){
            l1 = linear_poly(v1[2*j+1]-v1[2*j],v1[2*j]);
            l2 = linear_poly(v2[2*j+1]-v2[2*j],v2[2*j]);
            p = l1*l2;
            l1 = linear_poly(r1[2*j+1]-r1[2*j],r1[2*j]);
            l2 = linear_poly(r2[2*j+1]-r2[2*j],r2[2*j]);
            p_r = l1*l2;
            _p = linear_poly(v3[2*j+1]-v3[2*j],v3[2*j]);
            p.a = p.a + b*p_r.a;p.b = p.b + b*p_r.b - _p.a;p.c = p.c + b*p_r.c-_p.b;
            poly = poly + p* linear_poly(beta2[2*j+1]-beta2[2*j],beta2[2*j]);
        }
        if(poly.eval(0) + poly.eval(1) != y){
            printf("Error in sumcheck functionality %d\n",i);
            exit(-1);
        }
        
        challenges[i] = F::_random();
        y = poly.eval(challenges[i]);
        for(int j = 0; j < v1.size()/(1<<(i+1)); j++){
            v1[j] = challenges[i]*(v1[2*j+1]-v1[2*j]) + v1[2*j];
            v2[j] = challenges[i]*(v2[2*j+1]-v2[2*j]) + v2[2*j];
            v3[j] = challenges[i]*(v3[2*j+1]-v3[2*j]) + v3[2*j];
            r1[j] = challenges[i]*(r1[2*j+1]-r1[2*j]) + r1[2*j];
            r2[j] = challenges[i]*(r2[2*j+1]-r2[2*j]) + r2[2*j];
            beta2[j] = challenges[i]*(beta2[2*j+1]-beta2[2*j]) + beta2[2*j];
        }        
    }
    vector<F> ret;
    ret.push_back(v1[0]);ret.push_back(v2[0]);ret.push_back(v3[0]);
    ret.push_back(beta2[0]);ret.push_back(r1[0]);ret.push_back(r2[0]);
    ret.insert(ret.end(),challenges.begin(),challenges.end());
    return ret;

}

vector<F> quadratic_sumcheck_local(vector<F> final_v1, vector<F> final_v2, F y, int k, int _k, int N){
    
    
    fft(final_v1,(int)log2(final_v1.size()),true);
    fft(final_v2,(int)log2(final_v2.size()),true);
    
    F omega = getRootOfUnity(1+(int)log2(N));
    omega = omega.inv();
    F mul = F(1);
    for(int i = 0; i < final_v1.size(); i++){
        final_v1[i] = mul*final_v1[i];
        final_v2[i] = mul*final_v2[i];
        mul = mul*omega;
    }

    fft(final_v1,(int)log2(final_v1.size()),false);
    fft(final_v2,(int)log2(final_v2.size()),false);
    
    vector<F> v1(k),v2(k);    
    for(int i = 0; i < k; i++){
        v1[i] = final_v1[N*i/_k];
        v2[i] = final_v2[N*i/_k];
    }
    
    int rounds = (int)log2(k);
    vector<F> challenges(rounds);
    for(int i = 0; i < rounds; i++){
        quadratic_poly p = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
        linear_poly l1,l2;
        for(int j = 0; j < v1.size()/(1<<(i+1)); j++){
            l1 = linear_poly(v1[2*i+1]-v1[2*i],v1[2*i]);
            l2 = linear_poly(v2[2*i+1]-v2[2*i],v2[2*i]);
            p = p + l1*l2;
        }
        
        if(p.eval(0) + p.eval(1) != y){
            printf("Error in sumcheck functionality %d\n",i);
            exit(-1);
        }
        
        challenges[i] = F::_random();
        y = p.eval(challenges[i]);
        for(int j = 0; j < v1.size()/(1<<(i+1)); j++){
            v1[j] = challenges[i]*(v1[2*j+1]-v1[2*j]) + v1[2*j];
            v2[j] = challenges[i]*(v2[2*j+1]-v2[2*j]) + v2[2*j];
        }        
    }
    vector<F> ret;
    ret.push_back(v1[0]);ret.push_back(v2[0]);
    ret.insert(ret.end(),challenges.begin(),challenges.end());
    return ret;

}

vector<F> batch_sumcheck_local(vector<F> final_v1, vector<F> final_v2, 
                                    vector<F> final_v3, vector<F> final_v4, 
                                    vector<F> h1, vector<F> h2,
                                    F b, F y, int k, int _k, int N){
    
    
    fft(final_v1,(int)log2(final_v1.size()),true);
    fft(final_v2,(int)log2(final_v2.size()),true);
    fft(final_v3,(int)log2(final_v3.size()),true);
    fft(final_v4,(int)log2(final_v4.size()),true);
    fft(h1,(int)log2(h1.size()),true);
    fft(h2,(int)log2(h2.size()),true);
    
    F omega = getRootOfUnity(1+(int)log2(N));
    omega = omega.inv();
    F mul = F(1);
    for(int i = 0; i < final_v1.size(); i++){
        final_v1[i] = mul*final_v1[i];
        final_v2[i] = mul*final_v2[i];
        final_v3[i] = mul*final_v3[i];
        final_v4[i] = mul*final_v4[i];
        h1[i] = mul*h1[i];
        h2[i] = mul*h2[i];
        mul = mul*omega;
    }

    fft(final_v1,(int)log2(final_v1.size()),false);
    fft(final_v2,(int)log2(final_v2.size()),false);
    fft(final_v3,(int)log2(final_v3.size()),false);
    fft(final_v4,(int)log2(final_v4.size()),false);
    fft(h1,(int)log2(h1.size()),false);
    fft(h2,(int)log2(h2.size()),false);
    

    vector<F> v1(k),v2(k),v3(k),v4(k);
    vector<F> r1(k),r2(k);
    
    for(int i = 0; i < k; i++){
        v1[i] = final_v1[N*i/_k];
        v2[i] = final_v2[N*i/_k];
        v3[i] = final_v3[N*i/_k];
        v4[i] = final_v4[N*i/_k];
        r1[i] = h1[N*i/_k];
        r2[i] = h2[N*i/_k];
    }
    
    int rounds = (int)log2(k);
    vector<F> challenges(rounds);
    for(int i = 0; i < rounds; i++){
        quadratic_poly p = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
        quadratic_poly p_r = quadratic_poly(F_ZERO,F_ZERO,F_ZERO);
        linear_poly _p = linear_poly(F_ZERO,F_ZERO);
        linear_poly l1,l2;
        for(int j = 0; j < v1.size()/(1<<(i+1)); j++){
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
        
        if(p.eval(0) + p.eval(1) != y){
            printf("Error in sumcheck functionality %d\n",i);
            exit(-1);
        }
        
        challenges[i] = F::_random();
        y = p.eval(challenges[i]);
        for(int j = 0; j < v1.size()/(1<<(i+1)); j++){
            v1[j] = challenges[i]*(v1[2*j+1]-v1[2*j]) + v1[2*j];
            v2[j] = challenges[i]*(v2[2*j+1]-v2[2*j]) + v2[2*j];
            v3[j] = challenges[i]*(v3[2*j+1]-v3[2*j]) + v3[2*j];
            v4[j] = challenges[i]*(v4[2*j+1]-v4[2*j]) + v4[2*j];
            r1[j] = challenges[i]*(r1[2*j+1]-r1[2*j]) + r1[2*j];
            r2[j] = challenges[i]*(r2[2*j+1]-r2[2*j]) + r2[2*j];
        }        
    }
    vector<F> ret;
    ret.push_back(v1[0]);ret.push_back(v2[0]);ret.push_back(v3[0]);
    ret.push_back(v4[0]);ret.push_back(r1[0]);ret.push_back(r2[0]);
    ret.insert(ret.end(),challenges.begin(),challenges.end());
    return ret;

}


vector<pair<F,vector<F>>> F_zero_check_rest(F v1, F v2, F v3, F h1, F h2, 
                                            vector<F> &beta1, vector<F> &beta2, 
                                            F b, F y, int k, int _k, int N){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<u64> buff_u64(10);
    vector<F> buff,ret;

    if(rank == 0){
        vector<F> final_v1(N),final_v2(N),final_v3(N),final_h1(N),final_h2(N);
        final_v1[0] = v1;final_v2[0] = v2;final_v3[0] = v3;final_h1[0] = h1;final_h2[0] = h2;
        for(int i = 1; i < N; i++){
            MPI_Recv(buff_u64.data(),10,MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            field_vector_deserialize(buff_u64,buff);
            final_v1[i] = buff[0];final_v2[i] = buff[1];final_v3[i] = buff[2];final_h1[i] = buff[3];final_h2[i] = buff[4];
        }
        ret = zero_check_sumcheck_local(final_v1, final_v2, final_v3, final_h1, final_h2, beta1, beta2, b, y, k, _k, N);
        for(int i = 1; i < N; i++){
            field_vector_serialize(ret,buff_u64);
            MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        }
    }else{
        buff = {v1,v2,v3,h1,h2};
        field_vector_serialize(buff,buff_u64);
        MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD);
        buff_u64.clear();buff_u64.resize(2*(6+(int)log2(k)));
        MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        field_vector_deserialize(buff_u64,ret);        
    }
    vector<F> r;
    for(int i = 6; i < ret.size(); i++) r.push_back(ret[i]); 
    return {make_pair(ret[0],r),make_pair(ret[1],r),make_pair(ret[2],r),make_pair(ret[3],r),make_pair(ret[4],r),make_pair(ret[5],r)};
}

vector<pair<F,vector<F>>> F_batch_sumcheck_rest(F v1, F v2, F v3, F v4, F h1, F h2, 
                                            F b, F y, int k, int _k, int N){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<u64> buff_u64(12);
    vector<F> buff,ret;

    if(rank == 0){
        vector<F> final_v1(N),final_v2(N),final_v3(N),final_v4(N),final_h1(N),final_h2(N);
        final_v1[0] = v1;final_v2[0] = v2;final_v3[0] = v3;final_v4[0] = v4;final_h1[0] = h1;final_h2[0] = h2;
        for(int i = 1; i < N; i++){
            MPI_Recv(buff_u64.data(),12,MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            field_vector_deserialize(buff_u64,buff);
            final_v1[i] = buff[0];final_v2[i] = buff[1];final_v3[i] = buff[2];final_v4[i] = buff[3];final_h1[i] = buff[4];final_h2[i] = buff[5];
        }
        ret = batch_sumcheck_local(final_v1, final_v2, final_v3, final_v4, final_h1, final_h2, b, y, k, _k, N);
        for(int i = 1; i < N; i++){
            field_vector_serialize(ret,buff_u64);
            MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        }
    }else{
        buff = {v1,v2,v3,v4,h1,h2};
        field_vector_serialize(buff,buff_u64);
        MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD);
        buff_u64.clear();buff_u64.resize(2*(6+(int)log2(k)));
        MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        field_vector_deserialize(buff_u64,ret);        
    }
    vector<F> r;
    for(int i = 6; i < ret.size(); i++) r.push_back(ret[i]); 
    return {make_pair(ret[0],r),make_pair(ret[1],r),make_pair(ret[2],r),make_pair(ret[3],r),make_pair(ret[4],r),make_pair(ret[5],r)};
}


vector<pair<F,vector<F>>> F_quadratic_sumcheck_rest(F v1, F v2, F y, int k, int _k, int N){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<u64> buff_u64(4);
    vector<F> buff,ret;

    if(rank == 0){
        vector<F> final_v1(N),final_v2(N);
        final_v1[0] = v1;final_v2[0] = v2;
        for(int i = 1; i < N; i++){
            MPI_Recv(buff_u64.data(),4,MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            field_vector_deserialize(buff_u64,buff);
            final_v1[i] = buff[0];final_v2[i] = buff[1];
        }
        ret = quadratic_sumcheck_local(final_v1, final_v2, y, k, _k, N);
        for(int i = 1; i < N; i++){
            field_vector_serialize(ret,buff_u64);
            MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        }
    }else{
        buff = {v1,v2};
        field_vector_serialize(buff,buff_u64);
        MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD);
        buff_u64.clear();buff_u64.resize(2*(2+(int)log2(k)));
        MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        field_vector_deserialize(buff_u64,ret);        
    }
    vector<F> r;
    for(int i = 2; i < ret.size(); i++) r.push_back(ret[i]); 
    return {make_pair(ret[0],r),make_pair(ret[1],r)};
}


cubic_poly aggregate_cubic_poly(cubic_poly H, vector<F> &v, int k, int _k, int N){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    F a = F(0),b = F(0),c = F(0),d = F(0);
        
    vector<F> coef; coef.push_back(H.a);coef.push_back(H.b);coef.push_back(H.c),coef.push_back(H.d);
    vector<u64> coef_u;
    
    field_vector_serialize(coef,coef_u);
    if(rank == 0){
        vector<F> _a(N),_b(N),_c(N),_d(N);
        _a[0] = coef[0];_b[0] = coef[1];_c[0] = coef[2],_d[0] = coef[3]; 
        
        for(int i = 1; i < N; i++){
            MPI_Recv(coef_u.data(),8,MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            field_vector_deserialize(coef_u,coef);
            _a[i] = coef[0];_b[i] = coef[1];_c[i] = coef[2];_d[i] = coef[3];
        }
        vector<F> test_a;
        
        fft(_a,(int)log2(_a.size()),true);
        fft(_b,(int)log2(_a.size()),true);
        fft(_c,(int)log2(_a.size()),true);
        fft(_d,(int)log2(_a.size()),true);
        F omega = getRootOfUnity(1+(int)log2(N));
        omega = omega.inv();
        F mul = F(1);
        for(int i = 0; i < _a.size(); i++){
            _a[i] = mul*_a[i];
            _b[i] = mul*_b[i];
            _c[i] = mul*_c[i];
            _d[i] = mul*_d[i];
            mul = omega*mul;
        }
        //_a.resize(_k);
        fft(_a,(int)log2(_a.size()),false);
        //_b.resize(_k);
        fft(_b,(int)log2(_a.size()),false);
        //_c.resize(_k);
        fft(_c,(int)log2(_a.size()),false);
        //_d.resize(_k);
        fft(_d,(int)log2(_a.size()),false);
        
        /*
        for(int i = 0; i < _a.size(); i++){
            if(_a[i] + _b[i]+_c[i]+F(2)*_d[i] == 0){
                printf("OK %d\n",i);
            }
        }
        */
        
        for(int j = 0; j < v.size(); j++){
            
            a += v[j]*_a[N*j/_k];
            b += v[j]*_b[N*j/_k];
            c += v[j]*_c[N*j/_k];
            d += v[j]*_d[N*j/_k];
        }
        coef[0] = a;coef[1] = b;coef[2] = c;coef[3] = d;
        field_vector_serialize(coef,coef_u);
        for(int i = 1; i < N; i++){
            MPI_Send(coef_u.data(),8,MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        }       
         
    }else{
        MPI_Send(coef_u.data(),8,MPI_UINT64_T,0,0,MPI_COMM_WORLD);
        MPI_Recv(coef_u.data(),8,MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        field_vector_deserialize(coef_u,coef);
        a = coef[0];b = coef[1];c = coef[2];d = coef[3]; 
    }

    return cubic_poly(a,b,c,d);
}


F distributed_eval(vector<F> &poly, vector<F> &beta1, vector<F> &beta2, int N){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<u64> buff(2); 
    
    F y = F(0);
    for(int i = 0; i < poly.size(); i++){
        y += poly[i]*beta1[i];
    }
        
    if(rank == 0){
        vector<F> Y(N);Y[0] = y; 
        for(int i = 1; i < N; i++){
            MPI_Recv(buff.data(),2,MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            Y[i].real = buff[0];
            Y[i].img = buff[1];
        }
        y = 0;
        for(int i = 0; i < beta2.size(); i++){
            y += Y[i]*beta2[i];
        }
        buff = {y.real,y.img};
    }else{
        buff = {y.real,y.img};
        MPI_Send(buff.data(),2,MPI_UINT64_T,0,0,MPI_COMM_WORLD);
    }
    MPI_Bcast(buff.data(),2,MPI_UINT64_T,0,MPI_COMM_WORLD);
    y.real = buff[0];
    y.img = buff[1];
    return y;
}

vector<F> batch_ip(vector<vector<F>> &arr, vector<vector<vector<F>>> &v, int N, int k, int _k){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<F> Y(arr.size(),F(0));
    for(int i = 0; i < Y.size(); i++){
        for(int j = 0; j < arr[i].size(); j++){
            Y[i] += arr[i][j]*v[i][0][j];
        }
    }
    vector<u64> Y_int;
    if(rank == 0){
        vector<vector<F>> partial_Y(arr.size());
        for(int i = 0; i < partial_Y.size(); i++){
            partial_Y[i].resize(N);
            partial_Y[i][0] = Y[i];
        }
        Y_int.resize(Y.size()*2);
        for(int i = 1; i < N; i++){
            MPI_Recv(Y_int.data(),Y_int.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            field_vector_deserialize(Y_int,Y);
            for(int j = 0; j < Y.size(); j++) partial_Y[j][i] = Y[j];
        }
        Y.clear();Y.resize(arr.size(),F(0));
        for(int i = 0; i < partial_Y.size(); i++){
            fft(partial_Y[i],(int)log2(partial_Y[i].size()),true);
            F omega = getRootOfUnity(1+(int)log2(N)).inv();
            F mul = F(1);
            for(int j = 0; j < partial_Y[i].size(); j++){
                partial_Y[i][j] = mul*partial_Y[i][j];
                mul = mul*omega;
            }
            fft(partial_Y[i],(int)log2(partial_Y[i].size()),false);
            for(int j = 0; j < k; j++){
                Y[i] += v[i][1][j]*partial_Y[i][N*j/_k];
            }
        }
        field_vector_serialize(Y,Y_int);
        
    }else{
        field_vector_serialize(Y,Y_int);
        MPI_Send(Y_int.data(),Y_int.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD);
    }
    MPI_Bcast(Y_int.data(),Y_int.size(),MPI_UINT64_T,0,MPI_COMM_WORLD);
    if(rank != 0){
        field_vector_deserialize(Y_int,Y);
    }
    return Y;
}

vector<F> batch_distributed_eval(vector<vector<F>> &poly, vector<F> &beta1, vector<F> &beta2, int N){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<u64> buff(poly.size()*2); 
    
    vector<F> y(poly.size(),F(0));
    for(int i = 0; i < poly.size(); i++){
        for(int j  = 0; j < poly[i].size(); j++){
            y[i] += poly[i][j]*beta1[j];
        }
    }
    
    if(rank == 0){
        vector<F> Y(poly.size(),F(0));
        for(int i = 0; i < poly.size(); i++){
            Y[i] += beta2[0]*y[i];
        }
        for(int i = 1; i < N; i++){
            MPI_Recv(buff.data(),2*poly.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
            for(int j = 0; j < poly.size(); j++){
                F v; v.real = buff[2*j];v.img = buff[2*j+1];
                Y[j] += beta2[i]*v;
            }
        }
    
        field_vector_serialize(Y,buff);
    }else{
        field_vector_serialize(y,buff);
        MPI_Send(buff.data(),2*poly.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD);
    }
    MPI_Bcast(buff.data(),2*poly.size(),MPI_UINT64_T,0,MPI_COMM_WORLD);
    field_vector_deserialize(buff,y);
    return y;
}

void send_index(vector<vector<int>> &Data,vector<int> dim , int N){
    vector<int> buff;
    vector<int> dim_buff = dim;
    dim_buff.insert(dim_buff.end(),real_idx_dim.begin(),real_idx_dim.end());
    for(int i = 1; i < N; i++){
        MPI_Send(dim_buff.data(),dim_buff.size(),MPI_INT,i,0,MPI_COMM_WORLD);
        MPI_Send(Data[i].data(),Data[i].size(),MPI_INT,i,0,MPI_COMM_WORLD);
    }
}

void send_R1CS_matrixes(vector<vector<int>> &Data, int N){
    for(int i = 1; i < N; i++){
        MPI_Send(Data[i].data(),Data[i].size(),MPI_INT,i,0,MPI_COMM_WORLD);
    }
}

void parse_R1CS_matrixes(vector<int> &data, int N, int M){
    
    pA.resize(2*M/N); pB.resize(2*M/N); pC.resize(2*M/N);
    for(int i = 0; i < 2*M/N; i++){
        if(data[2*i] == -1){
            continue;
        }
        pA[i].resize(1);
        pA[i][0].first = data[2*i];
        pA[i][0].second = data[2*i+1];
    }
    for(int i = 0; i < 2*M/N; i++){
        if(data[2*i + 4*M/N] == -1){
            continue;
        }
        pB[i].resize(1);
        pB[i][0].first = data[2*i + 4*M/N];
        pB[i][0].second = data[2*i + 1 + 4*M/N];
    }
    for(int i = 0; i < 2*M/N; i++){
        if(data[2*i + 8*M/N] == -1){
            continue;
        }
        pC[i].resize(1);
        pC[i][0].first = data[2*i + 8*M/N];
        pC[i][0].second = data[2*i + 1 + 8*M/N];
    }
}

void receive_R1CS_matrixes(int N, int M){
    vector<int> data(12*M/N);
    MPI_Recv(data.data(),data.size(),MPI_INT,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
    parse_R1CS_matrixes(data,N,M);
}

void parse_index(vector<sparse_eval_data> &index,vector<int> &dim, vector<int> &data){
    int ctr = 0;
    for(int i = 0; i < index.size(); i++){
        index[i].FINAL_FR1.resize(dim[4*i]);
        index[i].FINAL_FR2.resize(dim[4*i+1]);
        index[i].RD1.resize(dim[4*i+2]);
        index[i].WR1.resize(dim[4*i+2]);
        index[i].IDX1.resize(dim[4*i+2]);
        index[i].RD2.resize(dim[4*i+3]);
        index[i].WR2.resize(dim[4*i+3]);
        index[i].IDX2.resize(dim[4*i+3]);
        for(int j = 0; j < index[i].FINAL_FR1.size(); j++){
            index[i].FINAL_FR1[j] = data[ctr++];
        }
        for(int j = 0; j < index[i].FINAL_FR2.size(); j++){
            index[i].FINAL_FR2[j] = data[ctr++];
        }
        for(int j = 0; j < index[i].RD1.size(); j++){
            index[i].RD1[j] = data[ctr++];
            index[i].RD2[j] = data[ctr++];
            index[i].WR1[j] = data[ctr++];
            index[i].WR2[j] = data[ctr++];
            index[i].IDX1[j] = data[ctr++];
            index[i].IDX2[j] = data[ctr++];
        }
    }

}

void receive_index(vector<sparse_eval_data> &index,vector<int> &dim){
    
    vector<int> buff(15);
    dim.clear();dim.resize(12);
    MPI_Recv(buff.data(),buff.size(),MPI_INT,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
    for(int i = 0; i < 12; i++){
        dim[i] =  buff[i];
    }
    for(int i = 12; i < 15; i++){
        real_idx_dim.push_back(buff[i]);
    }
    int size = 0;
    for(int i = 0; i < dim.size()/4; i++){
        size += dim[4*i];
        size += dim[4*i+1];
        size += 3*dim[4*i+2];
        size += 3*dim[4*i+3];
    }  
    vector<int> data(size);
    MPI_Recv(data.data(),data.size(),MPI_INT,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
    parse_index(index,dim, data);
}

void distribute_index(int N, int M,vector<sparse_eval_data> &index){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    index.resize(3);
    vector<int> dims;
        
    if(rank == 0){
        vector<sparse_eval_data> data;
        vector<vector<int>> parsed_data(N);
        generate_R1CS_matrixes(M);
        prepare_R1CS_data(A, B, C, logm, logn, data);
        for(int i = 0; i < data.size(); i++){
            dims.push_back(data[i].FINAL_FR1.size()/N);
            dims.push_back(data[i].FINAL_FR2.size()/N);
            dims.push_back(data[i].RD1.size()/N);
            dims.push_back(data[i].RD2.size()/N);
        }
        
        for(int k = 0; k < N; k++){
            for(int i = 0; i < data.size(); i++){
                for(int j = 0; j < data[i].FINAL_FR1.size()/N; j++){
                    parsed_data[k].push_back(data[i].FINAL_FR1[k*data[i].FINAL_FR1.size()/N+ j]);
                }
                for(int j = 0; j < data[i].FINAL_FR2.size()/N; j++){
                    parsed_data[k].push_back(data[i].FINAL_FR2[k*data[i].FINAL_FR2.size()/N+j]);
                }
                for(int j = 0; j < data[i].RD1.size()/N; j++){
                    parsed_data[k].push_back(data[i].RD1[k*data[i].RD1.size()/N + j]);
                    parsed_data[k].push_back(data[i].RD2[k*data[i].RD1.size()/N +j]);            
                    parsed_data[k].push_back(data[i].WR1[k*data[i].RD1.size()/N +j]);
                    parsed_data[k].push_back(data[i].WR2[k*data[i].RD1.size()/N +j]);            
                    parsed_data[k].push_back(data[i].IDX1[k*data[i].RD1.size()/N +j]);
                    parsed_data[k].push_back(data[i].IDX2[k*data[i].RD1.size()/N +j]);     
                }
            }    
        }

        //for(int i = 0; i < parsed_data[0].size(); i++){
        //    printf("%d\n",parsed_data[0][i]);
        //}
        send_index(parsed_data,dims , N);
        parse_index(index,dims,parsed_data[0]);
        vector<vector<int>> parsed_R1CS_matrixes(N);
        for(int i = 0; i < N; i++){
            parsed_R1CS_matrixes[i].resize(12*M/N,0);
            for(int j = 0; j < 2*M/N; j++){
                if(tA[i*2*M/N + j].size()){
                    parsed_R1CS_matrixes[i][2*j] = tA[i*2*M/N + j][0].first;
                    parsed_R1CS_matrixes[i][2*j+1] = tA[i*2*M/N + j][0].second;
                }else{
                    parsed_R1CS_matrixes[i][2*j] = -1;
                    parsed_R1CS_matrixes[i][2*j+1] = -1;
                }
            }
            for(int j = 0;  j < 2*M/N; j++){
                if(tB[i*2*M/N + j].size()){
                    parsed_R1CS_matrixes[i][2*j + 4*M/N] = tB[i*2*M/N + j][0].first;
                    parsed_R1CS_matrixes[i][2*j+1 + 4*M/N] = tB[i*2*M/N + j][0].second;
                }else{
                    parsed_R1CS_matrixes[i][2*j+ 4*M/N] = -1;
                    parsed_R1CS_matrixes[i][2*j+1+ 4*M/N] = -1;
                }
            }
            for(int j = 0; j < 2*M/N; j++){
                if(tC[i*2*M/N + j].size()){
                    parsed_R1CS_matrixes[i][2*j + 8*M/N] = tC[i*2*M/N + j][0].first;
                    parsed_R1CS_matrixes[i][2*j+1 + 8*M/N] = tC[i*2*M/N + j][0].second;
                }else{
                    parsed_R1CS_matrixes[i][2*j+ 8*M/N] = -1;
                    parsed_R1CS_matrixes[i][2*j+1+ 8*M/N] = -1;
                }
            }
        }
            
        send_R1CS_matrixes(parsed_R1CS_matrixes,N);        
        parse_R1CS_matrixes(parsed_R1CS_matrixes[0],N,M);
    }else{
        logm = (int)log2(M);
        logn = (int)log2(M)+1;
        
        receive_index(index,dims);
        receive_R1CS_matrixes(N,M);
    }
}


void compute_secret_shares(vector<F> &v, vector<vector<F>> &v_shares, int N, int k, int _k, bool privacy_preserving){
    v_shares.resize(N);
    F y = F(0);
    int counter = 0;
    for(int i = 0; i < N; i++){
        v_shares[i].resize(v.size()/k);
    }
    
    for(int i = 0; i < v.size()/k; i++){
        vector<F> buff(_k,F(0));
        for(int j = 0; j < k; j++){
            buff[j] = v[counter++];
        }
        for(int  j = k; j < _k; j++){
            if(privacy_preserving) buff[j] = random();
        }

        fft(buff,(int)log2(buff.size()),true);
        buff.resize(2*N,F(0));
        fft(buff,(int)log2(buff.size()),false);
        for(int  j = 0; j < N; j++){
            v_shares[j][i] = buff[2*j + 1];
        }
    }
}

#include "Fiat_Shamir.h"
#include "Distributed_Sumcheck.h"


void distribute_proving_data(vector<F> &vL, vector<F> &vR, vector<F> &vO, vector<F> &w, int N, int M, int _k, int k){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<u64> buff_u64;
    vector<F> buff;
    

    if(rank == 0){
        vector<F> L,R,O,W;
        vector<vector<F>> L_shares,R_shares,O_shares,W_shares;
        prepare_witness_data(M,W,L,R,O);

        
        
        compute_secret_shares(W,W_shares,N,k,_k,true);
        compute_secret_shares(L,L_shares,N,k,_k,true);
        compute_secret_shares(R,R_shares,N,k,_k,true);
        compute_secret_shares(O,O_shares,N,k,_k,true);

        vL = L_shares[0];
        vR = R_shares[0];
        vO = O_shares[0];
        w = W_shares[0];
        
        for(int i = 1; i < N; i++){
            buff = L_shares[i];buff.insert(buff.end(),R_shares[i].begin(),R_shares[i].end());
            buff.insert(buff.end(),O_shares[i].begin(),O_shares[i].end());
            buff.insert(buff.end(),W_shares[i].begin(),W_shares[i].end());
            field_vector_serialize(buff,buff_u64);
            MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        }
    }else{
        buff_u64.resize(2*((1<<logn) + 3*(1<<logm))/k);
        MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        field_vector_deserialize(buff_u64,buff);    
        vL.resize((1<<logm)/k);vR.resize((1<<logm)/k);vO.resize((1<<logm)/k);
        w.resize((1<<logn)/k);

        for(int i = 0; i < vL.size(); i++){
            vL[i] = buff[i];
        }
        for(int i = 0; i < vR.size(); i++){
            vR[i] = buff[i + vL.size()];
        }
        for(int i = 0; i < vO.size(); i++){
            vO[i] = buff[i + 2*vL.size()];
        }
        for(int i = 0; i < w.size(); i++){
            w[i] = buff[i + 3*vL.size()];
        }
        
    }

} 


void setup_randomness(vector<F> &R, vector<F> &_R, int N, int _k, int k){
    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank); //get my process id
    vector<u64> buff_u64;
    int logk = (int)log2(k);
    if(rank == 0){
        vector<F> random_values(k*(500 + 2*(logm + logn - 2*logk + 4) + 12+1));
        vector<vector<F>> R_shares;
        for(int i = 0; i < random_values.size(); i++) random_values[i] = 0;
        compute_secret_shares(random_values,R_shares,N,k,_k,true);
        R = R_shares[0];
        for(int i = 1; i < N; i++){
            field_vector_serialize(R_shares[i],buff_u64);
            MPI_Send(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,i,0,MPI_COMM_WORLD);
        }
    }else{
        buff_u64.resize(2*(500 + 2*(logm + logn- 2*logk + 4) + 12+1));
        MPI_Recv(buff_u64.data(),buff_u64.size(),MPI_UINT64_T,0,0,MPI_COMM_WORLD,MPI_STATUS_IGNORE);
        field_vector_deserialize(buff_u64,R);           
    }
}