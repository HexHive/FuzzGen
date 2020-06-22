// ------------------------------------------------------------------------------------------------
/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *
 *      ___        ___           ___           ___           ___           ___           ___
 *     /\__\      /\  \         /\__\         /\__\         /\__\         /\__\         /\  \
 *    /:/ _/_     \:\  \       /::|  |       /::|  |       /:/ _/_       /:/ _/_        \:\  \
 *   /:/ /\__\     \:\  \     /:/:|  |      /:/:|  |      /:/ /\  \     /:/ /\__\        \:\  \
 *  /:/ /:/  / ___  \:\  \   /:/|:|  |__   /:/|:|  |__   /:/ /::\  \   /:/ /:/ _/_   _____\:\  \
 * /:/_/:/  / /\  \  \:\__\ /:/ |:| /\__\ /:/ |:| /\__\ /:/__\/\:\__\ /:/_/:/ /\__\ /::::::::\__\
 * \:\/:/  /  \:\  \ /:/  / \/__|:|/:/  / \/__|:|/:/  / \:\  \ /:/  / \:\/:/ /:/  / \:\~~\~~\/__/
 *  \::/__/    \:\  /:/  /      |:/:/  /      |:/:/  /   \:\  /:/  /   \::/_/:/  /   \:\  \
 *   \:\  \     \:\/:/  /       |::/  /       |::/  /     \:\/:/  /     \:\/:/  /     \:\  \
 *    \:\__\     \::/  /        |:/  /        |:/  /       \::/  /       \::/  /       \:\__\
 *     \/__/      \/__/         |/__/         |/__/         \/__/         \/__/         \/__/
 *
 * FuzzGen - Automatic Fuzzer Generation
 * Version: v3.1
 *
 * Target Library: external/libhevc
 * Build Options: analysis=deep; arch=x64; permute=yes; failure=yes; 
 *                coalesce=yes; progressive=no; max-depth=4; seed=random;
 *                min-buflen=32; max-buflen=4096;
 *
 * Issues: -
 *
 * ~~~ THIS FILE HAS BEEN GENERATED AUTOMATICALLY BY *FUZZGEN* AT: 11-07-2019 11:25:03 PDT ~~~
 *
 */
// ------------------------------------------------------------------------------------------------
#include <cstdint>
#include <iostream>
#include <cstdlib>
#include <cassert>
#include <math.h>

/* headers for library includes */
#include "iv.h"
#include "ivd.h"
#include "ihevcd_cxa.h"


using namespace std;

// ------------------------------------------------------------------------------------------------
/* calculate the number of bytes needed to hold a factorial */
#define NBYTES_FOR_FACTORIAL(n) ((((uint64_t)ceil( log2(FACTORIAL[n]) ) + 7) & (uint64_t)~7) >> 3)

/* The first 20 factorials (to avoid calculations) */
const uint64_t FACTORIAL[] = {
    1,                  // 0!
    1,                  // 1!
    2,                  // 2!
    6,                  // 3!
    24,                 // 4!
    120,                // 5!
    720,                // 6!
    5040,               // 7!
    40320,              // 8!
    362880,             // 9!
    3628800,            // 10!
    39916800,           // 11!
    479001600,          // 12!
    6227020800,         // 13!
    87178291200,        // 14!
    1307674368000,      // 15!
    20922789888000,     // 16!
    355687428096000,    // 17!
    6402373705728000,   // 18!
    121645100408832000, // 19!
    2432902008176640000 // 20!
};


/* predefined sets */
const int32_t v_GSI[] = {1, 5, 9, 11, 12};
const int32_t v_uuw[] = {1, 8};
const int32_t v_Wiz[] = {0, 64};
const int32_t v_CjZ[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 263, 264, 265, 775, 10008};
const int32_t v_xUE[] = {0, 1};
const int32_t v_Uxf[] = {1, 2, 6, 2147483647};
const int32_t v_bRq[] = {0, 1};
const int32_t v_Izg[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 263, 264, 265, 775, 10008};
const int32_t v_SPG[] = {0, 1};
const int32_t v_btG[] = {1, 2, 6, 2147483647};
const int32_t v_hMb[] = {0, 1};
const int32_t v_EVH[] = {0, 4};
const int32_t v_bmE[] = {0, 15};
const int32_t v_ODP[] = {0, 64};
const int32_t v_BCC[] = {1, 8};
const int32_t v_rlv[] = {0, 64};


/* global variables */
uint8_t *perm;
uint8_t* dep_1063_8;
uint32_t dep_1040;
iv_obj_t *dep_1061;
uint32_t dep_1026;
uint8_t v_tYo_0[64];
uint8_t *v_tYo_1[64];
uint8_t v_zED[4096];
uint32_t dep_1076_8;
uint32_t dep_1076_16;
uint32_t dep_1076_276[64];
uint8_t v_DRS[512];
uint8_t v_aGg[4096];
uint8_t v_dgc[64][4096];
uint8_t v_cYx_0[64];
uint8_t *v_cYx_1[64];
uint8_t v_oQl_0[64];
uint8_t *v_oQl_1[64];


size_t buflen = 32; /* adaptable buffer length */
size_t nbufs = 2; /* total number of buffers */
size_t ninp  = 281; /* total number of other input bytes */


/* function declarations (used by function pointers), if any */
uint8_t* ihevca_aligned_malloc(uint8_t* p0, uint32_t p1, uint32_t p2) {
    return (uint8_t*) memalign(p1, p2);

}

void ihevca_aligned_free(uint8_t* p0, uint8_t* p1) {
    free(p1);

}



// ------------------------------------------------------------------------------------------------
//
// Find the k-th permutation (in lexicographic order) in a sequence of n numbers,
// without calculating the k-1 permutations first. This is done in O(n^2) time.
//
// Function returns an array[n] that contains the indices of the k-th permutation.
//
static uint8_t *kperm(uint8_t n, uint64_t k) {
    uint64_t d = 0, factorial = FACTORIAL[n];
    uint8_t  c = 0, i, pool[32];
    uint8_t  *perm = new uint8_t[32];


    /* Because we're using 64-bit numbers, the larger factorial that can fit in, is 20! */
    assert( n <= 20 );

    for (i=0; i<n; ++i) pool[i] = i;                // initialize pool

    k = (k % factorial) + 1;                        // to get the correct results, 1 <= k <= n!
    factorial /= n;                                 // start from (n-1)!


    for (i=0; i<n-1; factorial/=(n-1 - i++)) {      // for all (but last) elements
        /* find d, r such that: k = d(n!) + r, subject to: d >= 0 and 0 < r <= n! */
        /* (classic division doesn't work here, so we use iterative subtractions) */

        for (d=0; k>(d+1)*factorial; ++d);          // k < n! so loop runs in O(n)
        k -= d * factorial;                         // calculate r

        perm[c++] = pool[d];

        for (uint8_t j=d; j<n-1; ++j) {             // remove d-th element from pool
            pool[j] = pool[j+1];
        }
        pool[n-1] = 0;                              // optional
    }

    perm[c++] = pool[0];                            // last element is trivial

    return perm;
}


// ------------------------------------------------------------------------------------------------
//
// The interface for "eating" bytes from the random input. 
//
// When a corpus is used and codec libraries are fuzzed, eating from the input needs special
// care. The beginning of the random input it's very likely to a valid frame or a buffer that
// can achieve a deep coverage. By using the first bytes for path selection and for variable
// fuzzing, we essentially destroy the frame.
//
// To fix this problem we split the input in two parts. When a buffer is being fuzzed, we eat
// bytes from the beginning of the input. Otherwise we eat from the end. Hence, we preserve the
// corpus and the frames that they may contain.
//
class EatData {
public:
    /* class constructor (no need for destructor) */
    EatData(const uint8_t *data, size_t size, size_t ninp) :
            data(data), size(size), delimiter(size-1 > ninp ? size-1 - ninp : 0), 
            bwctr(size-1), fwctr(0) { }

    /* eat (backwards) an integer between 1 and 8 bytes (for other input) */
    uint64_t eatIntBw(uint8_t k) {
        uint64_t num = 0;


        assert(k > 0 && k < 9);                     // make sure that size is valid

        if (bwctr - k < delimiter) {                // ensure that there're enough data

            cout << "eatIntBw(): All input has been eaten. This is a FuzzGen bug!\n";
            cout << "size = " << size << ", delimiter = " << delimiter
                 << ", bwctr = " << bwctr << ", k = " << (int)k << "\n";

            exit(-1);                               // abort

        }

        for (uint8_t i=0; i<k; ++i) {               // build the number (in big endian)
            num |= (uint64_t)data[bwctr - i] << (i << 3);
        }

        bwctr -= k;                                 // update counter
        return num;
    }


    /* eat (forward) an integer between 1 and 8 bytes (for buffers) */
    uint64_t eatIntFw(uint8_t k) {
        uint64_t num = 0;

        
        assert(k > 0 && k < 9);                     // make sure that size is valid

        if (fwctr + k > delimiter) {                // ensure that there're enough data

            cout << "eatIntFw(): All input has been eaten. This is a FuzzGen bug!\n";
            cout << "size = " << size << ", delimiter = " << delimiter
                 << ", fwctr = " << fwctr << ", k = " << (int)k << "\n";        

            exit(-1);                               // abort
        }

        for (uint8_t i=0; i<k; ++i) {               // build the number (in big endian)
            num |= (uint64_t)data[fwctr + i] << (i << 3);
        }

        fwctr += k;                                 // update counter
        return num;
    }


    /* abbervations for common sizes */
    inline uint8_t  eat1() { return (uint8_t) eatIntBw(1); }
    inline uint16_t eat2() { return (uint16_t)eatIntBw(2); }
    inline uint32_t eat4() { return (uint32_t)eatIntBw(4); }
    inline uint64_t eat8() { return eatIntBw(8); }


    /* abbervations for common sizes */
    inline uint8_t  buf_eat1() { return (uint8_t) eatIntFw(1); }
    inline uint16_t buf_eat2() { return (uint16_t)eatIntFw(2); }
    inline uint32_t buf_eat4() { return (uint32_t)eatIntFw(4); }
    inline uint64_t buf_eat8() { return eatIntFw(8); }


    /* eat a buffer of arbitrary size (DEPRECATED) */
    inline const uint8_t *eatBuf(uint32_t k) {
        const uint8_t *buf = &data[bwctr];

        if (bwctr - k < delimiter) {                // ensure that there're enough data  

            cout << "eatBuf(): All input has been eaten. This is a FuzzGen bug!\n";

            exit(-1);                               // abort
        }

        bwctr -= k;                                 // update counter
        return buf;
    }


private:
    const uint8_t *data;                            // random data
    size_t        size;                             // and its size
    size_t        delimiter;                        // delimiter (between buffer and other data)
    uint32_t      bwctr, fwctr;                     // backward and forward counters
};


// ------------------------------------------------------------------------------------------------
//
// LibFuzzer's initialization routine.
//
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void) argc;
    (void) argv;

    cout << "[*] This fuzzer has been created by *FuzzGen*\n";

    return 0;
}


// ------------------------------------------------------------------------------------------------
//
// LibFuzzer's main processing routine.
//
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* min size needed for Eat() to work properly */
    if (size < 345 || size > 9497) return 0;

    /* all variables contain 3 random letters, so E cannot redefined */
    EatData E(data, size, ninp);

    buflen = (size - ninp) / nbufs - 1;             // find length of each buffer


    /* * * function pool #0 * * */
    //{
        // initializing argument 'ps_handle_gRA'

        // initializing argument 'pv_api_ip_uzZ'
        ihevcd_cxa_create_ip_t pv_api_ip_uzZ_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_uzZ_0 + 0) = 40; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_uzZ_0 + 4) = 5; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_uzZ_0 + 8) = v_GSI[E.eat1() % 5]; /* e_output_format */
        *(uint32_t*)((uint64_t)&pv_api_ip_uzZ_0 + 12) = 0; /* u4_share_disp_buf */
        *(uint64_t*)((uint64_t)&pv_api_ip_uzZ_0 + 16) = (uint64_t)ihevca_aligned_malloc; /* pf_aligned_alloc */
        *(uint64_t*)((uint64_t)&pv_api_ip_uzZ_0 + 24) = (uint64_t)ihevca_aligned_free; /* pf_aligned_free */
        *(uint8_t**)((uint64_t)&pv_api_ip_uzZ_0 + 32) = NULL; /* pv_mem_ctxt */

        ihevcd_cxa_create_ip_t *pv_api_ip_uzZ_1 = &pv_api_ip_uzZ_0;

        // initializing argument 'pv_api_op_owN'
        ihevcd_cxa_create_op_t pv_api_op_owN_0;

        *(uint32_t*)((uint64_t)&pv_api_op_owN_0 + 0) = 16; /* u4_size */

        uint8_t v_HTe_0 = E.eat1();
        *(uint8_t**)((uint64_t)&pv_api_op_owN_0 + 8) = &v_HTe_0; /* pv_handle */

        ihevcd_cxa_create_op_t *pv_api_op_owN_1 = &pv_api_op_owN_0;

        dep_1040 = ihevcd_cxa_api_function(NULL, pv_api_ip_uzZ_1, pv_api_op_owN_1); /* vertex #0 */
        dep_1063_8 = *(uint8_t**)((uint64_t)&pv_api_op_owN_0 + 8);	// Dependence family #1063_8 definition

    //}


    /* * * function pool #1 * * */
    //{
        // initializing argument 'ps_handle_Lgn'
        iv_obj_t *ps_handle_Lgn_0 = (iv_obj_t*)dep_1063_8;

        *(uint32_t*)((uint64_t)ps_handle_Lgn_0 + 0) = 24; /* u4_size */
        *(uint64_t*)((uint64_t)ps_handle_Lgn_0 + 8) = (uint64_t)ihevcd_cxa_api_function; /* pv_fxns */

        // Dependence family #1061 Definition
        dep_1061 = (iv_obj_t *)ps_handle_Lgn_0;
        // initializing argument 'pv_api_ip_bMl'
        ihevcd_cxa_ctl_set_num_cores_ip_t pv_api_ip_bMl_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_bMl_0 + 0) = 16; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_bMl_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_bMl_0 + 8) = 7; /* e_sub_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_bMl_0 + 12) = v_uuw[E.eat1() % 2]; /* u4_num_cores */
        ihevcd_cxa_ctl_set_num_cores_ip_t *pv_api_ip_bMl_1 = &pv_api_ip_bMl_0;

        // initializing argument 'pv_api_op_BwP'
        ihevcd_cxa_ctl_set_num_cores_op_t pv_api_op_BwP_0;

        *(uint32_t*)((uint64_t)&pv_api_op_BwP_0 + 0) = 8; /* u4_size */
        ihevcd_cxa_ctl_set_num_cores_op_t *pv_api_op_BwP_1 = &pv_api_op_BwP_0;

        dep_1040 = ihevcd_cxa_api_function(dep_1061, pv_api_ip_bMl_1, pv_api_op_BwP_1); /* vertex #1 */

    //}


    /* * * function pool #2 * * */
    //{
        // initializing argument 'pv_api_ip_dYQ'
        ihevcd_cxa_ctl_set_processor_ip_t pv_api_ip_dYQ_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_dYQ_0 + 0) = 24; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_dYQ_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_dYQ_0 + 8) = 8; /* e_sub_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_dYQ_0 + 12) = 1; /* u4_arch */
        *(uint32_t*)((uint64_t)&pv_api_ip_dYQ_0 + 16) = 0; /* u4_soc */
        ihevcd_cxa_ctl_set_processor_ip_t *pv_api_ip_dYQ_1 = &pv_api_ip_dYQ_0;

        // initializing argument 'pv_api_op_mlx'
        ihevcd_cxa_ctl_set_processor_op_t pv_api_op_mlx_0;

        *(uint32_t*)((uint64_t)&pv_api_op_mlx_0 + 0) = 8; /* u4_size */
        ihevcd_cxa_ctl_set_processor_op_t *pv_api_op_mlx_1 = &pv_api_op_mlx_0;

        dep_1040 = ihevcd_cxa_api_function(dep_1061, pv_api_ip_dYQ_1, pv_api_op_mlx_1); /* vertex #2 */

    //}


    /* * * function pool #3 * * */
    //{
        // initializing argument 'pv_api_ip_Jac'
        ivd_ctl_flush_ip_t pv_api_ip_Jac_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_Jac_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_Jac_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_Jac_0 + 8) = 4; /* e_sub_cmd */
        ivd_ctl_flush_ip_t *pv_api_ip_Jac_1 = &pv_api_ip_Jac_0;

        // initializing argument 'pv_api_op_Sfs'
        ivd_ctl_flush_op_t pv_api_op_Sfs_0;

        *(uint32_t*)((uint64_t)&pv_api_op_Sfs_0 + 0) = 8; /* u4_size */
        ivd_ctl_flush_op_t *pv_api_op_Sfs_1 = &pv_api_op_Sfs_0;

        dep_1026 = ihevcd_cxa_api_function(dep_1061, pv_api_ip_Jac_1, pv_api_op_Sfs_1); /* vertex #15 */

    //}


    /* * * function pool #4 * * */
    //{
        // initializing argument 'pv_api_ip_BHX'
        ivd_video_decode_ip_t pv_api_ip_BHX_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_BHX_0 + 0) = 800; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_BHX_0 + 4) = 8; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_BHX_0 + 8) = 0; /* u4_ts */
        *(uint32_t*)((uint64_t)&pv_api_ip_BHX_0 + 12) = 0 /* DEAD */; /* u4_num_Bytes */

        uint8_t v_BTl_0 = 0;
        *(uint8_t**)((uint64_t)&pv_api_ip_BHX_0 + 16) = &v_BTl_0; /* pv_stream_buffer */
        *(uint32_t*)((uint64_t)&pv_api_ip_BHX_0 + 24) = v_Wiz[E.eat1() % 2]; /* u4_num_bufs */

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            v_tYo_0[i_0] = 0;
            v_tYo_1[i_0] = &v_tYo_0[i_0];
        }

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint8_t**)((uint64_t)&pv_api_ip_BHX_0 + 32 + i_0*sizeof(uint8_t)) = v_tYo_1[i_0]; /* pu1_bufs */
        }


        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint32_t*)((uint64_t)&pv_api_ip_BHX_0 + 544 + i_0*sizeof(uint32_t)) = buflen; /* u4_min_out_buf_size */
        }


        ivd_video_decode_ip_t *pv_api_ip_BHX_1 = &pv_api_ip_BHX_0;

        // initializing argument 'pv_api_op_Hrf'
        ivd_video_decode_op_t pv_api_op_Hrf_0;

        *(uint32_t*)((uint64_t)&pv_api_op_Hrf_0 + 0) = 136; /* u4_size */

        ivd_video_decode_op_t *pv_api_op_Hrf_1 = &pv_api_op_Hrf_0;

        dep_1026 = ihevcd_cxa_api_function(dep_1061, pv_api_ip_BHX_1, pv_api_op_Hrf_1); /* vertex #16 */

    //}


    /* * * function pool #5 * * */
    //{
        // initializing argument 'pv_api_ip_LXr'
        ivd_rel_display_frame_ip_t pv_api_ip_LXr_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_LXr_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_LXr_0 + 4) = 10; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_LXr_0 + 8) = 0 /* DEAD */; /* u4_disp_buf_id */
        ivd_rel_display_frame_ip_t *pv_api_ip_LXr_1 = &pv_api_ip_LXr_0;

        // initializing argument 'pv_api_op_Pfq'
        ivd_rel_display_frame_op_t pv_api_op_Pfq_0;

        *(uint32_t*)((uint64_t)&pv_api_op_Pfq_0 + 0) = 8; /* u4_size */
        ivd_rel_display_frame_op_t *pv_api_op_Pfq_1 = &pv_api_op_Pfq_0;

        ihevcd_cxa_api_function(dep_1061, pv_api_ip_LXr_1, pv_api_op_Pfq_1); /* vertex #17 */

    //}


    /* * * function pool #6 * * */
    //{
        // initializing argument 'pv_api_ip_Zdc'
        ivd_ctl_set_config_ip_t pv_api_ip_Zdc_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_Zdc_0 + 0) = 28; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_Zdc_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_Zdc_0 + 8) = v_CjZ[E.eat1() % 14]; /* e_sub_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_Zdc_0 + 12) = v_xUE[E.eat1() % 2]; /* e_vid_dec_mode */
        *(uint32_t*)((uint64_t)&pv_api_ip_Zdc_0 + 16) = 0; /* u4_disp_wd */
        *(uint32_t*)((uint64_t)&pv_api_ip_Zdc_0 + 20) = v_Uxf[E.eat1() % 4]; /* e_frm_skip_mode */
        *(uint32_t*)((uint64_t)&pv_api_ip_Zdc_0 + 24) = v_bRq[E.eat1() % 2]; /* e_frm_out_mode */
        ivd_ctl_set_config_ip_t *pv_api_ip_Zdc_1 = &pv_api_ip_Zdc_0;

        // initializing argument 'pv_api_op_oTZ'
        ivd_ctl_set_config_op_t pv_api_op_oTZ_0;

        *(uint32_t*)((uint64_t)&pv_api_op_oTZ_0 + 0) = 8; /* u4_size */
        ivd_ctl_set_config_op_t *pv_api_op_oTZ_1 = &pv_api_op_oTZ_0;

        dep_1040 = ihevcd_cxa_api_function(dep_1061, pv_api_ip_Zdc_1, pv_api_op_oTZ_1); /* vertex #3 */

    //}


    /* * * function pool #7 * * */
    //{
        // initializing argument 'pv_api_ip_nBW'
        ivd_video_decode_ip_t pv_api_ip_nBW_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_nBW_0 + 0) = 800; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_nBW_0 + 4) = 8; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_nBW_0 + 8) = 0; /* u4_ts */
        *(uint32_t*)((uint64_t)&pv_api_ip_nBW_0 + 12) = buflen; /* u4_num_Bytes */

        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            v_zED[i_0] = E.buf_eat1();
        }

        *(uint8_t**)((uint64_t)&pv_api_ip_nBW_0 + 16) = (uint8_t*)v_zED; /* pv_stream_buffer */

        ivd_video_decode_ip_t *pv_api_ip_nBW_1 = &pv_api_ip_nBW_0;

        // initializing argument 'pv_api_op_Wfx'
        ivd_video_decode_op_t pv_api_op_Wfx_0;

        *(uint32_t*)((uint64_t)&pv_api_op_Wfx_0 + 0) = 136; /* u4_size */

        ivd_video_decode_op_t *pv_api_op_Wfx_1 = &pv_api_op_Wfx_0;

        dep_1040 = ihevcd_cxa_api_function(dep_1061, pv_api_ip_nBW_1, pv_api_op_Wfx_1); /* vertex #4 */

    //}


    /* * * function pool #8 * * */
    //{
        // initializing argument 'pv_api_ip_fUp'
        ivd_ctl_getbufinfo_ip_t pv_api_ip_fUp_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_fUp_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_fUp_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_fUp_0 + 8) = 5; /* e_sub_cmd */
        ivd_ctl_getbufinfo_ip_t *pv_api_ip_fUp_1 = &pv_api_ip_fUp_0;

        // initializing argument 'pv_api_op_akD'
        ivd_ctl_getbufinfo_op_t pv_api_op_akD_0;

        *(uint32_t*)((uint64_t)&pv_api_op_akD_0 + 0) = 532; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_op_akD_0 + 8) = E.eat4(); /* u4_num_disp_bufs */
        *(uint32_t*)((uint64_t)&pv_api_op_akD_0 + 16) = E.eat4(); /* u4_min_num_out_bufs */

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint32_t*)((uint64_t)&pv_api_op_akD_0 + 276 + i_0*sizeof(uint32_t)) = E.eat4(); /* u4_min_out_buf_size */
        }

        ivd_ctl_getbufinfo_op_t *pv_api_op_akD_1 = &pv_api_op_akD_0;

        dep_1040 = ihevcd_cxa_api_function(dep_1061, pv_api_ip_fUp_1, pv_api_op_akD_1); /* vertex #5 */
        dep_1076_8 = *(uint32_t*)((uint64_t)&pv_api_op_akD_0 + 8);	// Dependence family #1076_8 definition

        dep_1076_16 = *(uint32_t*)((uint64_t)&pv_api_op_akD_0 + 16);	// Dependence family #1076_16 definition

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            dep_1076_276[i_0] = *(uint32_t*)((uint64_t)&pv_api_op_akD_0 + 276 + i_0*sizeof(uint32_t));	// Dependence family #1076_276 definition
        }


    //}


    /* * * function pool #9 * * */
    //{
        // initializing argument 'pv_api_ip_Sef'
        ivd_set_display_frame_ip_t pv_api_ip_Sef_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_Sef_0 + 0) = 49680; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_Sef_0 + 4) = 11; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_Sef_0 + 8) = dep_1076_8; /* num_disp_bufs */

        for (uint64_t i_0=0; i_0<64; ++i_0) {
        }

        ivd_set_display_frame_ip_t *pv_api_ip_Sef_1 = &pv_api_ip_Sef_0;

        // initializing argument 'pv_api_op_COo'
        ivd_set_display_frame_op_t pv_api_op_COo_0;

        *(uint32_t*)((uint64_t)&pv_api_op_COo_0 + 0) = 8; /* u4_size */
        ivd_set_display_frame_op_t *pv_api_op_COo_1 = &pv_api_op_COo_0;

        dep_1040 = ihevcd_cxa_api_function(dep_1061, pv_api_ip_Sef_1, pv_api_op_COo_1); /* vertex #6 */

    //}


    /* * * function pool #10 * * */
    //{
        // initializing argument 'pv_api_ip_EjK'
        ihevcd_cxa_ctl_get_frame_dimensions_ip_t pv_api_ip_EjK_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_EjK_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_EjK_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_EjK_0 + 8) = 263; /* e_sub_cmd */
        ihevcd_cxa_ctl_get_frame_dimensions_ip_t *pv_api_ip_EjK_1 = &pv_api_ip_EjK_0;

        // initializing argument 'pv_api_op_dRe'
        ihevcd_cxa_ctl_get_frame_dimensions_op_t pv_api_op_dRe_0;

        *(uint32_t*)((uint64_t)&pv_api_op_dRe_0 + 0) = 80; /* u4_size */
        ihevcd_cxa_ctl_get_frame_dimensions_op_t *pv_api_op_dRe_1 = &pv_api_op_dRe_0;

        dep_1040 = ihevcd_cxa_api_function(dep_1061, pv_api_ip_EjK_1, pv_api_op_dRe_1); /* vertex #7 */

    //}


    /* * * function pool #11 * * */
    //{
        // initializing argument 'pv_api_ip_zai'
        ihevcd_cxa_ctl_get_vui_params_ip_t pv_api_ip_zai_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_zai_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_zai_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_zai_0 + 8) = 264; /* e_sub_cmd */
        ihevcd_cxa_ctl_get_vui_params_ip_t *pv_api_ip_zai_1 = &pv_api_ip_zai_0;

        // initializing argument 'pv_api_op_lrI'
        ihevcd_cxa_ctl_get_vui_params_op_t pv_api_op_lrI_0;

        *(uint32_t*)((uint64_t)&pv_api_op_lrI_0 + 0) = 124; /* u4_size */
        ihevcd_cxa_ctl_get_vui_params_op_t *pv_api_op_lrI_1 = &pv_api_op_lrI_0;

        dep_1040 = ihevcd_cxa_api_function(dep_1061, pv_api_ip_zai_1, pv_api_op_lrI_1); /* vertex #8 */

    //}


    /* * * function pool #12 * * */
    //{
        // initializing argument 'pv_api_ip_KWr'
        ivd_ctl_set_config_ip_t pv_api_ip_KWr_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_KWr_0 + 0) = 28; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_KWr_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_KWr_0 + 8) = v_Izg[E.eat1() % 14]; /* e_sub_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_KWr_0 + 12) = v_SPG[E.eat1() % 2]; /* e_vid_dec_mode */
        *(uint32_t*)((uint64_t)&pv_api_ip_KWr_0 + 16) = 0; /* u4_disp_wd */
        *(uint32_t*)((uint64_t)&pv_api_ip_KWr_0 + 20) = v_btG[E.eat1() % 4]; /* e_frm_skip_mode */
        *(uint32_t*)((uint64_t)&pv_api_ip_KWr_0 + 24) = v_hMb[E.eat1() % 2]; /* e_frm_out_mode */
        ivd_ctl_set_config_ip_t *pv_api_ip_KWr_1 = &pv_api_ip_KWr_0;

        // initializing argument 'pv_api_op_VJm'
        ivd_ctl_set_config_op_t pv_api_op_VJm_0;

        *(uint32_t*)((uint64_t)&pv_api_op_VJm_0 + 0) = 8; /* u4_size */
        ivd_ctl_set_config_op_t *pv_api_op_VJm_1 = &pv_api_op_VJm_0;

        dep_1040 = ihevcd_cxa_api_function(dep_1061, pv_api_ip_KWr_1, pv_api_op_VJm_1); /* vertex #9 */

    //}


    /* * * function pool #13 * * */
    //{
        // initializing argument 'pv_api_ip_Vpg'
        ihevcd_cxa_ctl_degrade_ip_t pv_api_ip_Vpg_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_Vpg_0 + 0) = 24; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_Vpg_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_Vpg_0 + 8) = 775; /* e_sub_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_Vpg_0 + 12) = v_EVH[E.eat1() % 2]; /* i4_degrade_pics */
        *(uint32_t*)((uint64_t)&pv_api_ip_Vpg_0 + 16) = 0; /* i4_nondegrade_interval */
        *(uint32_t*)((uint64_t)&pv_api_ip_Vpg_0 + 20) = v_bmE[E.eat1() % 2]; /* i4_degrade_type */
        ihevcd_cxa_ctl_degrade_ip_t *pv_api_ip_Vpg_1 = &pv_api_ip_Vpg_0;

        // initializing argument 'pv_api_op_zYf'
        ihevcd_cxa_ctl_degrade_op_t pv_api_op_zYf_0;

        *(uint32_t*)((uint64_t)&pv_api_op_zYf_0 + 0) = 8; /* u4_size */
        ihevcd_cxa_ctl_degrade_op_t *pv_api_op_zYf_1 = &pv_api_op_zYf_0;

        ihevcd_cxa_api_function(dep_1061, pv_api_ip_Vpg_1, pv_api_op_zYf_1); /* vertex #18 */

    //}


    /* * * function pool #14 * * */
    //{
        // initializing argument 'pv_api_ip_INh'
        ivd_ctl_getversioninfo_ip_t pv_api_ip_INh_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_INh_0 + 0) = 32; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_INh_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_INh_0 + 8) = 6; /* e_sub_cmd */

        for (uint64_t i_0=0; i_0<512; ++i_0) {
            v_DRS[i_0] = 0 /* WO */;
        }

        *(uint8_t**)((uint64_t)&pv_api_ip_INh_0 + 16) = v_DRS; /* pv_version_buffer */
        *(uint32_t*)((uint64_t)&pv_api_ip_INh_0 + 24) = buflen; /* u4_version_buffer_size */
        ivd_ctl_getversioninfo_ip_t *pv_api_ip_INh_1 = &pv_api_ip_INh_0;

        // initializing argument 'pv_api_op_FSv'
        ivd_ctl_getversioninfo_op_t pv_api_op_FSv_0;

        *(uint32_t*)((uint64_t)&pv_api_op_FSv_0 + 0) = 8; /* u4_size */
        ivd_ctl_getversioninfo_op_t *pv_api_op_FSv_1 = &pv_api_op_FSv_0;

        ihevcd_cxa_api_function(dep_1061, pv_api_ip_INh_1, pv_api_op_FSv_1); /* vertex #19 */

    //}


    /* * * function pool #15 * * */
    //{
        // initializing argument 'pv_api_ip_bFE'
        ivd_video_decode_ip_t pv_api_ip_bFE_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_bFE_0 + 0) = 800; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_bFE_0 + 4) = 8; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_bFE_0 + 8) = 0; /* u4_ts */
        *(uint32_t*)((uint64_t)&pv_api_ip_bFE_0 + 12) = buflen; /* u4_num_Bytes */

        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            v_aGg[i_0] = E.buf_eat1();
        }

        *(uint8_t**)((uint64_t)&pv_api_ip_bFE_0 + 16) = (uint8_t*)v_aGg; /* pv_stream_buffer */
        *(uint32_t*)((uint64_t)&pv_api_ip_bFE_0 + 24) = dep_1076_16; /* u4_num_bufs */

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            for (uint64_t i_1=0; i_1<buflen; ++i_1) {
                v_dgc[i_0][i_1] = 0;
            }
            *(uint8_t**)((uint64_t)&pv_api_ip_bFE_0 + 32 + i_0*sizeof(uint8_t)) = (uint8_t*)v_dgc[i_0]; /* pu1_bufs */
        }


        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint32_t*)((uint64_t)&pv_api_ip_bFE_0 + 544 + i_0*sizeof(uint32_t)) = dep_1076_276[i_0]; /* u4_min_out_buf_size */
        }


        ivd_video_decode_ip_t *pv_api_ip_bFE_1 = &pv_api_ip_bFE_0;

        // initializing argument 'pv_api_op_VoB'
        ivd_video_decode_op_t pv_api_op_VoB_0;

        *(uint32_t*)((uint64_t)&pv_api_op_VoB_0 + 0) = 136; /* u4_size */

        ivd_video_decode_op_t *pv_api_op_VoB_1 = &pv_api_op_VoB_0;

        dep_1040 = ihevcd_cxa_api_function(dep_1061, pv_api_ip_bFE_1, pv_api_op_VoB_1); /* vertex #10 */

    //}


    /* * * function pool #16 * * */
    //{
        // initializing argument 'pv_api_ip_qDO'
        ivd_ctl_flush_ip_t pv_api_ip_qDO_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_qDO_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_qDO_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_qDO_0 + 8) = 4; /* e_sub_cmd */
        ivd_ctl_flush_ip_t *pv_api_ip_qDO_1 = &pv_api_ip_qDO_0;

        // initializing argument 'pv_api_op_TWw'
        ivd_ctl_flush_op_t pv_api_op_TWw_0;

        *(uint32_t*)((uint64_t)&pv_api_op_TWw_0 + 0) = 8; /* u4_size */
        ivd_ctl_flush_op_t *pv_api_op_TWw_1 = &pv_api_op_TWw_0;

        dep_1026 = ihevcd_cxa_api_function(dep_1061, pv_api_ip_qDO_1, pv_api_op_TWw_1); /* vertex #24 */

    //}


    /* * * function pool #17 * * */
    //{
        // initializing argument 'pv_api_ip_cfQ'
        ivd_video_decode_ip_t pv_api_ip_cfQ_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_cfQ_0 + 0) = 800; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_cfQ_0 + 4) = 8; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_cfQ_0 + 8) = 0; /* u4_ts */
        *(uint32_t*)((uint64_t)&pv_api_ip_cfQ_0 + 12) = 0 /* DEAD */; /* u4_num_Bytes */

        uint8_t v_rKO_0 = 0;
        *(uint8_t**)((uint64_t)&pv_api_ip_cfQ_0 + 16) = &v_rKO_0; /* pv_stream_buffer */
        *(uint32_t*)((uint64_t)&pv_api_ip_cfQ_0 + 24) = v_ODP[E.eat1() % 2]; /* u4_num_bufs */

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            v_cYx_0[i_0] = 0;
            v_cYx_1[i_0] = &v_cYx_0[i_0];
        }

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint8_t**)((uint64_t)&pv_api_ip_cfQ_0 + 32 + i_0*sizeof(uint8_t)) = v_cYx_1[i_0]; /* pu1_bufs */
        }


        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint32_t*)((uint64_t)&pv_api_ip_cfQ_0 + 544 + i_0*sizeof(uint32_t)) = buflen; /* u4_min_out_buf_size */
        }


        ivd_video_decode_ip_t *pv_api_ip_cfQ_1 = &pv_api_ip_cfQ_0;

        // initializing argument 'pv_api_op_Gyx'
        ivd_video_decode_op_t pv_api_op_Gyx_0;

        *(uint32_t*)((uint64_t)&pv_api_op_Gyx_0 + 0) = 136; /* u4_size */

        ivd_video_decode_op_t *pv_api_op_Gyx_1 = &pv_api_op_Gyx_0;

        dep_1026 = ihevcd_cxa_api_function(dep_1061, pv_api_ip_cfQ_1, pv_api_op_Gyx_1); /* vertex #25 */

    //}


    /* * * function pool #18 * * */
    //{
        // initializing argument 'pv_api_ip_CWn'
        ivd_rel_display_frame_ip_t pv_api_ip_CWn_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_CWn_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_CWn_0 + 4) = 10; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_CWn_0 + 8) = 0 /* DEAD */; /* u4_disp_buf_id */
        ivd_rel_display_frame_ip_t *pv_api_ip_CWn_1 = &pv_api_ip_CWn_0;

        // initializing argument 'pv_api_op_WUv'
        ivd_rel_display_frame_op_t pv_api_op_WUv_0;

        *(uint32_t*)((uint64_t)&pv_api_op_WUv_0 + 0) = 8; /* u4_size */
        ivd_rel_display_frame_op_t *pv_api_op_WUv_1 = &pv_api_op_WUv_0;

        ihevcd_cxa_api_function(dep_1061, pv_api_ip_CWn_1, pv_api_op_WUv_1); /* vertex #26 */

    //}


    /* * * function pool #19 * * */
    //{
        // initializing argument 'pv_api_ip_FrO'
        ivd_ctl_reset_ip_t pv_api_ip_FrO_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_FrO_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_FrO_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_FrO_0 + 8) = 2; /* e_sub_cmd */
        ivd_ctl_reset_ip_t *pv_api_ip_FrO_1 = &pv_api_ip_FrO_0;

        // initializing argument 'pv_api_op_lDQ'
        ivd_ctl_reset_op_t pv_api_op_lDQ_0;

        *(uint32_t*)((uint64_t)&pv_api_op_lDQ_0 + 0) = 8; /* u4_size */
        ivd_ctl_reset_op_t *pv_api_op_lDQ_1 = &pv_api_op_lDQ_0;

        dep_1040 = ihevcd_cxa_api_function(dep_1061, pv_api_ip_FrO_1, pv_api_op_lDQ_1); /* vertex #27 */

    //}


    /* * * function pool #20 * * */
    //{
        // initializing argument 'pv_api_ip_Kbr'
        ihevcd_cxa_ctl_set_num_cores_ip_t pv_api_ip_Kbr_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_Kbr_0 + 0) = 16; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_Kbr_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_Kbr_0 + 8) = 7; /* e_sub_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_Kbr_0 + 12) = v_BCC[E.eat1() % 2]; /* u4_num_cores */
        ihevcd_cxa_ctl_set_num_cores_ip_t *pv_api_ip_Kbr_1 = &pv_api_ip_Kbr_0;

        // initializing argument 'pv_api_op_pNi'
        ihevcd_cxa_ctl_set_num_cores_op_t pv_api_op_pNi_0;

        *(uint32_t*)((uint64_t)&pv_api_op_pNi_0 + 0) = 8; /* u4_size */
        ihevcd_cxa_ctl_set_num_cores_op_t *pv_api_op_pNi_1 = &pv_api_op_pNi_0;

        dep_1040 = ihevcd_cxa_api_function(dep_1061, pv_api_ip_Kbr_1, pv_api_op_pNi_1); /* vertex #11 */

    //}


    /* * * function pool #21 * * */
    //{
        // initializing argument 'pv_api_ip_yxJ'
        ihevcd_cxa_ctl_set_processor_ip_t pv_api_ip_yxJ_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_yxJ_0 + 0) = 24; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_yxJ_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_yxJ_0 + 8) = 8; /* e_sub_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_yxJ_0 + 12) = 1; /* u4_arch */
        *(uint32_t*)((uint64_t)&pv_api_ip_yxJ_0 + 16) = 0; /* u4_soc */
        ihevcd_cxa_ctl_set_processor_ip_t *pv_api_ip_yxJ_1 = &pv_api_ip_yxJ_0;

        // initializing argument 'pv_api_op_dpJ'
        ihevcd_cxa_ctl_set_processor_op_t pv_api_op_dpJ_0;

        *(uint32_t*)((uint64_t)&pv_api_op_dpJ_0 + 0) = 8; /* u4_size */
        ihevcd_cxa_ctl_set_processor_op_t *pv_api_op_dpJ_1 = &pv_api_op_dpJ_0;

        dep_1040 = ihevcd_cxa_api_function(dep_1061, pv_api_ip_yxJ_1, pv_api_op_dpJ_1); /* vertex #12 */

    //}


    /* * * function pool #22 * * */
    //{
        // initializing argument 'pv_api_ip_pau'
        ihevcd_cxa_ctl_get_sei_mastering_params_ip_t pv_api_ip_pau_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_pau_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_pau_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_pau_0 + 8) = 265; /* e_sub_cmd */
        ihevcd_cxa_ctl_get_sei_mastering_params_ip_t *pv_api_ip_pau_1 = &pv_api_ip_pau_0;

        // initializing argument 'pv_api_op_ytW'
        ihevcd_cxa_ctl_get_sei_mastering_params_op_t pv_api_op_ytW_0;

        *(uint32_t*)((uint64_t)&pv_api_op_ytW_0 + 0) = 32; /* u4_size */
        ihevcd_cxa_ctl_get_sei_mastering_params_op_t *pv_api_op_ytW_1 = &pv_api_op_ytW_0;

        dep_1040 = ihevcd_cxa_api_function(dep_1061, pv_api_ip_pau_1, pv_api_op_ytW_1); /* vertex #13 */

    //}


    /* * * function pool #23 * * */
    //{
        // initializing argument 'pv_api_ip_zJc'
        ivd_rel_display_frame_ip_t pv_api_ip_zJc_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_zJc_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_zJc_0 + 4) = 10; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_zJc_0 + 8) = 0 /* DEAD */; /* u4_disp_buf_id */
        ivd_rel_display_frame_ip_t *pv_api_ip_zJc_1 = &pv_api_ip_zJc_0;

        // initializing argument 'pv_api_op_JxF'
        ivd_rel_display_frame_op_t pv_api_op_JxF_0;

        *(uint32_t*)((uint64_t)&pv_api_op_JxF_0 + 0) = 8; /* u4_size */
        ivd_rel_display_frame_op_t *pv_api_op_JxF_1 = &pv_api_op_JxF_0;

        ihevcd_cxa_api_function(dep_1061, pv_api_ip_zJc_1, pv_api_op_JxF_1); /* vertex #28 */

    //}


    /* * * function pool #24 * * */
    //{
        // initializing argument 'pv_api_ip_acA'
        ivd_rel_display_frame_ip_t pv_api_ip_acA_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_acA_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_acA_0 + 4) = 10; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_acA_0 + 8) = 0 /* DEAD */; /* u4_disp_buf_id */
        ivd_rel_display_frame_ip_t *pv_api_ip_acA_1 = &pv_api_ip_acA_0;

        // initializing argument 'pv_api_op_GvS'
        ivd_rel_display_frame_op_t pv_api_op_GvS_0;

        *(uint32_t*)((uint64_t)&pv_api_op_GvS_0 + 0) = 8; /* u4_size */
        ivd_rel_display_frame_op_t *pv_api_op_GvS_1 = &pv_api_op_GvS_0;

        ihevcd_cxa_api_function(dep_1061, pv_api_ip_acA_1, pv_api_op_GvS_1); /* vertex #23 */

    //}


    /* * * function pool #25 * * */
    //{
        // initializing argument 'pv_api_ip_ozp'
        ivd_ctl_flush_ip_t pv_api_ip_ozp_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_ozp_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_ozp_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_ozp_0 + 8) = 4; /* e_sub_cmd */
        ivd_ctl_flush_ip_t *pv_api_ip_ozp_1 = &pv_api_ip_ozp_0;

        // initializing argument 'pv_api_op_XLP'
        ivd_ctl_flush_op_t pv_api_op_XLP_0;

        *(uint32_t*)((uint64_t)&pv_api_op_XLP_0 + 0) = 8; /* u4_size */
        ivd_ctl_flush_op_t *pv_api_op_XLP_1 = &pv_api_op_XLP_0;

        dep_1026 = ihevcd_cxa_api_function(dep_1061, pv_api_ip_ozp_1, pv_api_op_XLP_1); /* vertex #20 */

    //}


    /* * * function pool #26 * * */
    //{
        // initializing argument 'pv_api_ip_doS'
        ivd_video_decode_ip_t pv_api_ip_doS_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_doS_0 + 0) = 800; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_doS_0 + 4) = 8; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_doS_0 + 8) = 0; /* u4_ts */
        *(uint32_t*)((uint64_t)&pv_api_ip_doS_0 + 12) = 0 /* DEAD */; /* u4_num_Bytes */

        uint8_t v_uoA_0 = 0;
        *(uint8_t**)((uint64_t)&pv_api_ip_doS_0 + 16) = &v_uoA_0; /* pv_stream_buffer */
        *(uint32_t*)((uint64_t)&pv_api_ip_doS_0 + 24) = v_rlv[E.eat1() % 2]; /* u4_num_bufs */

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            v_oQl_0[i_0] = 0;
            v_oQl_1[i_0] = &v_oQl_0[i_0];
        }

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint8_t**)((uint64_t)&pv_api_ip_doS_0 + 32 + i_0*sizeof(uint8_t)) = v_oQl_1[i_0]; /* pu1_bufs */
        }


        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint32_t*)((uint64_t)&pv_api_ip_doS_0 + 544 + i_0*sizeof(uint32_t)) = buflen; /* u4_min_out_buf_size */
        }


        ivd_video_decode_ip_t *pv_api_ip_doS_1 = &pv_api_ip_doS_0;

        // initializing argument 'pv_api_op_hqx'
        ivd_video_decode_op_t pv_api_op_hqx_0;

        *(uint32_t*)((uint64_t)&pv_api_op_hqx_0 + 0) = 136; /* u4_size */

        ivd_video_decode_op_t *pv_api_op_hqx_1 = &pv_api_op_hqx_0;

        dep_1026 = ihevcd_cxa_api_function(dep_1061, pv_api_ip_doS_1, pv_api_op_hqx_1); /* vertex #21 */

    //}


    /* * * function pool #27 * * */
    //{
        // initializing argument 'pv_api_ip_bPb'
        ivd_rel_display_frame_ip_t pv_api_ip_bPb_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_bPb_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_bPb_0 + 4) = 10; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_bPb_0 + 8) = 0 /* DEAD */; /* u4_disp_buf_id */
        ivd_rel_display_frame_ip_t *pv_api_ip_bPb_1 = &pv_api_ip_bPb_0;

        // initializing argument 'pv_api_op_gGB'
        ivd_rel_display_frame_op_t pv_api_op_gGB_0;

        *(uint32_t*)((uint64_t)&pv_api_op_gGB_0 + 0) = 8; /* u4_size */
        ivd_rel_display_frame_op_t *pv_api_op_gGB_1 = &pv_api_op_gGB_0;

        ihevcd_cxa_api_function(dep_1061, pv_api_ip_bPb_1, pv_api_op_gGB_1); /* vertex #22 */

    //}


    /* * * function pool #28 * * */
    //{
        // initializing argument 'pv_api_ip_Lth'
        ivd_delete_ip_t pv_api_ip_Lth_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_Lth_0 + 0) = 8; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_Lth_0 + 4) = 6; /* e_cmd */
        ivd_delete_ip_t *pv_api_ip_Lth_1 = &pv_api_ip_Lth_0;

        // initializing argument 'pv_api_op_bGx'
        ivd_delete_op_t pv_api_op_bGx_0;

        *(uint32_t*)((uint64_t)&pv_api_op_bGx_0 + 0) = 8; /* u4_size */
        ivd_delete_op_t *pv_api_op_bGx_1 = &pv_api_op_bGx_0;

        dep_1040 = ihevcd_cxa_api_function(dep_1061, pv_api_ip_Lth_1, pv_api_op_bGx_1); /* vertex #14 */

    //}




    return 0;
}

// ------------------------------------------------------------------------------------------------
