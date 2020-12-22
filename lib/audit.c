#include <pbc/pbc.h>
#include <stdio.h>
#include <gmp.h>
#include <time.h>

#include <print-utils.h>
#include <handlefile.h>
#include <logging.h>
#include <sha256.h>
#include <audit.h>
#include <bls.h>

struct tag_t* generate_tag(tag_param_t* tag_params)
{
    struct file_piece_t*    fpiece      = tag_params->fpiece;
    uint32_t                index       = tag_params->index;

    struct element_s alpha[1];
    element_t f_i;
    struct element_s* new_elem;
    struct tag_t* tag;
    char* string;
    mpz_t integer;
    
    tag             = (struct tag_t*)malloc(sizeof(struct tag_t));
    tag->index      = tag_params->index;
    string          = hexstring((unsigned char*)(fpiece->data),(int)fpiece->blk_size);
    new_elem        = bls_hash_int(index,tag_params->pairing); // new_elem = H(i)
    
    element_init_G1(tag->sigma,tag_params->pairing);
    element_init_same_as(alpha,tag_params->alpha);
    element_init_Zr(f_i,tag_params->pairing);
    element_set(alpha,tag_params->alpha);
    mpz_init_set_str(integer,string,16);

    element_set_mpz(f_i,integer);
    element_pow_zn(alpha,alpha,f_i); // alpha = alpha^F[i]
    element_mul(new_elem,new_elem,alpha); // new_elem = H(i).(alpha^F[i])
        
    element_pow_zn(new_elem,new_elem,tag_params->secret_x); //new_elem = (H(i).(alpha^F[i]))^x

    element_init_same_as(tag->sigma,new_elem);
    element_set(tag->sigma,new_elem);

    return tag;
}

void set_tags(struct file_t* file, tag_param_t* params)
{
    for(int i=0;i<file->nr_blocks;i++) {
        params->fpiece      = file->pieces+i;
        params->index       = i;
        params->fpiece->tag = generate_tag(params);
        
        // element_printf("Sigma[%d]:%B\n",params->fpiece->tag->index,params->fpiece->tag->sigma);
    }
}

struct query_response_t* query(struct file_t* file,struct query_t query_obj)
{
    struct query_response_t* response;
    response = (struct query_response_t*)malloc(sizeof(struct query_response_t));

    /*
     *  code
     */
    printf("Timing begins...\n");
    // struct timeval tv0,  tv1[query_obj.query_length], tv2[query_obj.query_length], tv3;
    // gettimeofday(&tv0, NULL);
    clock_t t0 = clock();
    response->pairing = query_obj.pairing;
    struct pairing_s* pairing = query_obj.pairing;
    element_init_G1(response->sigma,pairing);
    element_set1(response->sigma);
    element_init_Zr(response->mu,pairing);
    int i=0;
    for(;i < query_obj.query_length;i++) {
        element_t temp;
        element_init_G1(temp,query_obj.pairing);

        // gettimeofday(&tv1[i], NULL);
        element_pow_zn(temp,
            file->pieces[query_obj.indices[i]].tag->sigma, &query_obj.nu[i]);
        // gettimeofday(&tv2[i], NULL);
        // element_printf("Index %d: %B\n", i, file->pieces[query_obj.indices[i]].tag->sigma);

        element_mul(response->sigma,temp,response->sigma);
        mpz_t integer;

        mpz_init_set_str(
            integer,
            (const char*)hexstring((unsigned char*)file->pieces[query_obj.indices[i]].data,
                            file->pieces[query_obj.indices[i]].blk_size),
            16);

        element_init_Zr(temp,query_obj.pairing);
        element_set_mpz(temp,integer);
        element_mul(temp,temp, &query_obj.nu[i]);
        element_add(response->mu,response->mu,temp);

        mpz_clear(integer);
        // element_free(temp);
    }
    // gettimeofday(&tv3, NULL);
    clock_t t1 = clock();
    printf("Timing ends...\n");

    // printf ("t1 - t0 = %f milliseconds\n",
    //         (double) (tv1[0].tv_usec - tv0.tv_usec) / 1000 +
    //         (double) (tv1[0].tv_sec - tv0.tv_sec) * 1000);

    // printf ("t2 - t1 = %f milliseconds\n",
    //         (double) (tv2[0].tv_usec - tv1[0].tv_usec) / 1000 +
    //         (double) (tv2[0].tv_sec - tv1[0].tv_sec) * 1000);

    // printf ("Total= %f milliseconds\n",
    //         (double) (tv3.tv_usec - tv0.tv_usec) / 1000 +
    //         (double) (tv3.tv_sec - tv0.tv_sec) * 1000);

    double time_taken = ((double) (t1 - t0))/ (CLOCKS_PER_SEC / 1000); // in ms
    printf("prove(%d) took %f seconds to execute \n", query_obj.query_length, time_taken);

    return response;
}

/**
 * g, alpha -> u: generators of G
 */
enum audit_result verify_storage(struct file_t* file, 
    struct query_response_t response,struct query_t query_obj, 
    element_t g,element_t alpha,element_t pubkey)
{
    int first = 1;
    element_t temp1,temp2,temp5;
    element_init_GT(temp1,query_obj.pairing);
    element_init_GT(temp2,query_obj.pairing);
    element_init_G1(temp5,query_obj.pairing);
    
    pairing_apply(temp1,response.sigma,g,query_obj.pairing); // temp1 = e(sigma,g)

    for(int i=0;i<query_obj.query_length;i++) {
        element_t temp3,temp4;
        element_init_G1(temp3,query_obj.pairing);
        element_init_G1(temp4,query_obj.pairing);

        struct element_s* new_elem = bls_hash_int
            (query_obj.indices[i],
            query_obj.pairing);
        // element_printf("Hash(%lu):%B\n",query_obj.indices[i],new_elem);
        element_pow_zn(temp3,new_elem,query_obj.nu+i); // temp3 = H(i)^v(i)
        // element_printf("temp3:%B\n",temp3);
        if(first) {
            element_pow_zn(temp4,alpha,response.mu); // temp4 = alpha^mu
            // element_printf("temp4:%B\n",temp4);
            element_mul(temp3,temp3,temp4); // temp3 = temp3 x temp4
            // element_printf("temp3:%B\n",temp3);
            first = 0;
            element_set(temp5,temp3);
        }
        else {
            element_mul(temp5,temp5,temp3); // temp5 = temp5*temp3
        }
        // element_printf("temp5:%B\n",temp5);
        
    }
    pairing_apply(temp2,temp5,pubkey,query_obj.pairing);
    element_printf("LHS:%B\nRHS:%B\n",temp1,temp2);

    /*
     *  element_cmp() returns 0 if the elements are the same.
     */
    int ret = element_cmp(temp1,temp2);
    if(!ret) 
        return PASS;
    
    return FAIL;
}