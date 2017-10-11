#include <stdio.h>

#include <logging.h>
#include <bls.h>
#include <audit.h>
#include <handlefile.h>

void main(int argc, char *argv[])
{
    log_level = LOG_QUIET;
    struct file_t *f = get_file_blocks(argv[1]);
    //pairing_t* pairing = init_pairing();

    tag_param_t params;
    element_t g,pubkey;

    pairing_init_set_buf(params.pairing, a1_param, strlen(a1_param));

    element_init_Zr(params.secret_x,params.pairing);
    element_init_G1(params.alpha,params.pairing);
    element_init_G1(pubkey,params.pairing);
    element_init_G1(g,params.pairing);

    element_random(params.secret_x);
    element_random(params.alpha);
    element_random(g);

    element_mul(pubkey,g,params.secret_x);

    set_tags(f,&params);

    struct query_t query_obj = {
        .query_length = 2,
    };
    query_obj.pairing   = params.pairing;
    query_obj.indices   = malloc(sizeof(uint32_t) * query_obj.query_length);
    query_obj.nu        = malloc(sizeof(struct element_s) * query_obj.query_length);

    query_obj.indices[0] = 0;
    query_obj.indices[1] = 1;

    for(int i=0;i<query_obj.query_length;i++) {
        element_init_Zr(query_obj.nu+i,params.pairing);
        element_random(query_obj.nu+i);
    }
    
    struct query_response_t* response = query(f,query_obj);
    element_printf("Sigma:%B\nMu:%B\n",response->sigma,response->mu);

    int result = verify_storage(f,*response,query_obj,g,params.alpha,pubkey);
    printf("Response: %d\n",result);
}