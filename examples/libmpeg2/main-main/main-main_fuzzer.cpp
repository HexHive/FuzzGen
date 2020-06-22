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
 * Target Library: external/libmpeg2
 * Build Options: analysis=basic; arch=x64; permute=yes; failure=yes; 
 *                coalesce=yes; progressive=no; max-depth=4; seed=31337;
 *                min-buflen=32; max-buflen=4096;
 *
 * Issues: -
 *
 * ~~~ THIS FILE HAS BEEN GENERATED AUTOMATICALLY BY *FUZZGEN* AT: 27-02-2019 01:28:31 EET ~~~
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
#include "impeg2d.h"
#include "ivd.h"


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


/* global variables */
uint8_t *perm;
uint32_t dep_1088_8;
uint32_t dep_1069;
iv_mem_rec_t v_EtZ[0];
uint32_t dep_1090_8;
uint64_t dep_1086;
uint32_t dep_1062;
uint32_t dep_1098_8;
uint32_t dep_1098_16;
uint32_t dep_1098_276[64];
uint8_t v_wQE[4096];
uint32_t dep_1111_8;
uint8_t v_pdZ[512];
uint8_t v_rjU[4096];
uint8_t v_rHg[64][4096];
uint32_t dep_1048;
uint8_t v_RQd_0[64];
uint8_t *v_RQd_1[64];
uint8_t v_ajZ_0[64];
uint8_t *v_ajZ_1[64];
uint8_t v_cNq_0[64];
uint8_t *v_cNq_1[64];
iv_mem_rec_t v_KlJ[0];


size_t buflen = 32; /* adaptable buffer length */
size_t nbufs = 2; /* total number of buffers */
size_t ninp  = 3; /* total number of other input bytes */


/* function declarations (used by function pointers), if any */


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
    if (size < 67 || size > 9219) return 0;

    /* all variables contain 3 random letters, so E cannot redefined */
    EatData E(data, size, ninp);

    buflen = (size - ninp) / nbufs - 1;             // find length of each buffer


    /* * * function pool #0 * * */
    //{
        // initializing argument 'ps_handle_iWq'

        // initializing argument 'pv_api_ip_mCT'
        iv_num_mem_rec_ip_t pv_api_ip_mCT_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_mCT_0 + 0) = 8; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_mCT_0 + 4) = 0; /* e_cmd */
        iv_num_mem_rec_ip_t *pv_api_ip_mCT_1 = &pv_api_ip_mCT_0;

        // initializing argument 'pv_api_op_UJu'
        iv_num_mem_rec_op_t pv_api_op_UJu_0;

        *(uint32_t*)((uint64_t)&pv_api_op_UJu_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_op_UJu_0 + 8) = 0 /* DEAD */; /* u4_num_mem_rec */
        iv_num_mem_rec_op_t *pv_api_op_UJu_1 = &pv_api_op_UJu_0;

        dep_1069 = impeg2d_api_function(NULL, pv_api_ip_mCT_1, pv_api_op_UJu_1); /* vertex #0 */
        dep_1088_8 = *(uint32_t*)((uint64_t)&pv_api_op_UJu_0 + 8);	// Dependence family #1088_8 definition

    //}


    /* * * function pool #1 * * */
    //{
        // initializing argument 'ps_handle_MQT'

        // initializing argument 'pv_api_ip_FZP'
        impeg2d_fill_mem_rec_ip_t pv_api_ip_FZP_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_FZP_0 + 0) = 40; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_FZP_0 + 4) = 1; /* e_cmd */

        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            v_EtZ[i_0];

        }

        *(iv_mem_rec_t**)((uint64_t)&pv_api_ip_FZP_0 + 8) = (iv_mem_rec_t*)v_EtZ;
        *(uint32_t*)((uint64_t)&pv_api_ip_FZP_0 + 16) = 0 /* DEAD */; /* u4_max_frm_wd */
        *(uint32_t*)((uint64_t)&pv_api_ip_FZP_0 + 20) = 0 /* DEAD */; /* u4_max_frm_ht */

        *(uint32_t*)((uint64_t)&pv_api_ip_FZP_0 + 24) = 0; /* u4_share_disp_buf */
        *(uint32_t*)((uint64_t)&pv_api_ip_FZP_0 + 28) = 11; /* e_output_format */
        *(uint32_t*)((uint64_t)&pv_api_ip_FZP_0 + 32) = 0; /* u4_deinterlace */
        impeg2d_fill_mem_rec_ip_t *pv_api_ip_FZP_1 = &pv_api_ip_FZP_0;

        // initializing argument 'pv_api_op_Lro'
        impeg2d_fill_mem_rec_op_t pv_api_op_Lro_0;

        *(uint32_t*)((uint64_t)&pv_api_op_Lro_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_op_Lro_0 + 8) = 0 /* DEAD */; /* u4_disp_buf_id */

        impeg2d_fill_mem_rec_op_t *pv_api_op_Lro_1 = &pv_api_op_Lro_0;

        dep_1069 = impeg2d_api_function(NULL, pv_api_ip_FZP_1, pv_api_op_Lro_1); /* vertex #1 */
        dep_1090_8 = *(uint32_t*)((uint64_t)&pv_api_op_Lro_0 + 8);	// Dependence family #1090_8 definition

    //}


    /* * * function pool #2 * * */
    //{
        // initializing argument 'ps_handle_wUJ'
        uint64_t ps_handle_wUJ_0 = (uint64_t)impeg2d_api_function;

        // Dependence family #1086 Definition
        dep_1086 = (uint64_t )ps_handle_wUJ_0;
        // initializing argument 'pv_api_ip_fcK'
        impeg2d_init_ip_t pv_api_ip_fcK_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_fcK_0 + 0) = 40; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_fcK_0 + 4) = 3; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_fcK_0 + 8) = dep_1090_8; /* u4_num_mem_rec */
        *(uint32_t*)((uint64_t)&pv_api_ip_fcK_0 + 12) = 0 /* DEAD */; /* u4_frm_max_wd */
        *(uint32_t*)((uint64_t)&pv_api_ip_fcK_0 + 16) = 0 /* DEAD */; /* u4_frm_max_ht */
        *(uint32_t*)((uint64_t)&pv_api_ip_fcK_0 + 20) = 11; /* e_output_format */

        iv_mem_rec_t v_FCf_0;

        *(iv_mem_rec_t**)((uint64_t)&pv_api_ip_fcK_0 + 24) = &v_FCf_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_fcK_0 + 32) = 0; /* u4_share_disp_buf */
        *(uint32_t*)((uint64_t)&pv_api_ip_fcK_0 + 36) = 0; /* u4_deinterlace */
        impeg2d_init_ip_t *pv_api_ip_fcK_1 = &pv_api_ip_fcK_0;

        // initializing argument 'pv_api_op_SFp'
        impeg2d_init_op_t pv_api_op_SFp_0;

        *(uint32_t*)((uint64_t)&pv_api_op_SFp_0 + 0) = 8; /* u4_size */

        impeg2d_init_op_t *pv_api_op_SFp_1 = &pv_api_op_SFp_0;

        dep_1062 = impeg2d_api_function(dep_1086, pv_api_ip_fcK_1, pv_api_op_SFp_1); /* vertex #2 */

    //}


    /* * * function pool #3 * * */
    //{
        // initializing argument 'pv_api_ip_KmN'
        ivd_ctl_getbufinfo_ip_t pv_api_ip_KmN_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_KmN_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_KmN_0 + 4) = 5; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_KmN_0 + 8) = 5; /* e_sub_cmd */
        ivd_ctl_getbufinfo_ip_t *pv_api_ip_KmN_1 = &pv_api_ip_KmN_0;

        // initializing argument 'pv_api_op_qfZ'
        ivd_ctl_getbufinfo_op_t pv_api_op_qfZ_0;

        *(uint32_t*)((uint64_t)&pv_api_op_qfZ_0 + 0) = 532; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_op_qfZ_0 + 8) = 0 /* DEAD */; /* u4_num_disp_bufs */
        *(uint32_t*)((uint64_t)&pv_api_op_qfZ_0 + 16) = 0 /* DEAD */; /* u4_min_num_out_bufs */

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint32_t*)((uint64_t)&pv_api_op_qfZ_0 + 276 + i_0*sizeof(uint32_t)) = 0 /* DEAD */; /* u4_min_out_buf_size */
        }

        ivd_ctl_getbufinfo_op_t *pv_api_op_qfZ_1 = &pv_api_op_qfZ_0;

        dep_1062 = impeg2d_api_function(dep_1086, pv_api_ip_KmN_1, pv_api_op_qfZ_1); /* vertex #3 */
        dep_1098_8 = *(uint32_t*)((uint64_t)&pv_api_op_qfZ_0 + 8);	// Dependence family #1098_8 definition

        dep_1098_16 = *(uint32_t*)((uint64_t)&pv_api_op_qfZ_0 + 16);	// Dependence family #1098_16 definition

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            dep_1098_276[i_0] = *(uint32_t*)((uint64_t)&pv_api_op_qfZ_0 + 276 + i_0*sizeof(uint32_t));	// Dependence family #1098_276 definition
        }


    //}


    /* * * function pool #4 * * */
    //{
        // initializing argument 'pv_api_ip_QuK'
        impeg2d_ctl_set_num_cores_ip_t pv_api_ip_QuK_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_QuK_0 + 0) = 16; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_QuK_0 + 4) = 5; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_QuK_0 + 8) = 7; /* e_sub_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_QuK_0 + 12) = 1; /* u4_num_cores */
        impeg2d_ctl_set_num_cores_ip_t *pv_api_ip_QuK_1 = &pv_api_ip_QuK_0;

        // initializing argument 'pv_api_op_Wxa'
        impeg2d_ctl_set_num_cores_op_t pv_api_op_Wxa_0;

        *(uint32_t*)((uint64_t)&pv_api_op_Wxa_0 + 0) = 8; /* u4_size */
        impeg2d_ctl_set_num_cores_op_t *pv_api_op_Wxa_1 = &pv_api_op_Wxa_0;

        dep_1062 = impeg2d_api_function(dep_1086, pv_api_ip_QuK_1, pv_api_op_Wxa_1); /* vertex #4 */

    //}


    /* * * function pool #5 * * */
    //{
        // initializing argument 'pv_api_ip_EaX'
        impeg2d_ctl_set_processor_ip_t pv_api_ip_EaX_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_EaX_0 + 0) = 24; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_EaX_0 + 4) = 5; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_EaX_0 + 8) = 8; /* e_sub_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_EaX_0 + 12) = 1; /* u4_arch */
        *(uint32_t*)((uint64_t)&pv_api_ip_EaX_0 + 16) = 0; /* u4_soc */
        impeg2d_ctl_set_processor_ip_t *pv_api_ip_EaX_1 = &pv_api_ip_EaX_0;

        // initializing argument 'pv_api_op_CDv'
        impeg2d_ctl_set_processor_op_t pv_api_op_CDv_0;

        *(uint32_t*)((uint64_t)&pv_api_op_CDv_0 + 0) = 8; /* u4_size */
        impeg2d_ctl_set_processor_op_t *pv_api_op_CDv_1 = &pv_api_op_CDv_0;

        dep_1062 = impeg2d_api_function(dep_1086, pv_api_ip_EaX_1, pv_api_op_CDv_1); /* vertex #5 */

    //}


    /* * * function pool #6 * * */
    //{
        // initializing argument 'pv_api_ip_fpZ'
        ivd_ctl_set_config_ip_t pv_api_ip_fpZ_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_fpZ_0 + 0) = 28; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_fpZ_0 + 4) = 5; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_fpZ_0 + 8) = 1; /* e_sub_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_fpZ_0 + 12) = 1; /* e_vid_dec_mode */
        *(uint32_t*)((uint64_t)&pv_api_ip_fpZ_0 + 16) = 0; /* u4_disp_wd */
        *(uint32_t*)((uint64_t)&pv_api_ip_fpZ_0 + 20) = 2147483647; /* e_frm_skip_mode */
        *(uint32_t*)((uint64_t)&pv_api_ip_fpZ_0 + 24) = 0; /* e_frm_out_mode */
        ivd_ctl_set_config_ip_t *pv_api_ip_fpZ_1 = &pv_api_ip_fpZ_0;

        // initializing argument 'pv_api_op_Wgb'
        ivd_ctl_set_config_op_t pv_api_op_Wgb_0;

        *(uint32_t*)((uint64_t)&pv_api_op_Wgb_0 + 0) = 8; /* u4_size */
        ivd_ctl_set_config_op_t *pv_api_op_Wgb_1 = &pv_api_op_Wgb_0;

        dep_1062 = impeg2d_api_function(dep_1086, pv_api_ip_fpZ_1, pv_api_op_Wgb_1); /* vertex #6 */

    //}


    /* * * function pool #7 * * */
    //{
        // initializing argument 'pv_api_ip_ZDc'
        ivd_video_decode_ip_t pv_api_ip_ZDc_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_ZDc_0 + 0) = 800; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_ZDc_0 + 4) = 6; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_ZDc_0 + 8) = 0; /* u4_ts */
        *(uint32_t*)((uint64_t)&pv_api_ip_ZDc_0 + 12) = buflen; /* u4_num_Bytes */

        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            v_wQE[i_0] = E.buf_eat1();
        }

        *(uint8_t**)((uint64_t)&pv_api_ip_ZDc_0 + 16) = (uint8_t*)v_wQE; /* pv_stream_buffer */

        ivd_video_decode_ip_t *pv_api_ip_ZDc_1 = &pv_api_ip_ZDc_0;

        // initializing argument 'pv_api_op_IIB'
        ivd_video_decode_op_t pv_api_op_IIB_0;

        *(uint32_t*)((uint64_t)&pv_api_op_IIB_0 + 0) = 136; /* u4_size */

        ivd_video_decode_op_t *pv_api_op_IIB_1 = &pv_api_op_IIB_0;

        dep_1062 = impeg2d_api_function(dep_1086, pv_api_ip_ZDc_1, pv_api_op_IIB_1); /* vertex #7 */

    //}


    /* * * function pool #8 * * */
    //{
        // initializing argument 'pv_api_ip_zmM'
        ivd_ctl_getbufinfo_ip_t pv_api_ip_zmM_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_zmM_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_zmM_0 + 4) = 5; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_zmM_0 + 8) = 5; /* e_sub_cmd */
        ivd_ctl_getbufinfo_ip_t *pv_api_ip_zmM_1 = &pv_api_ip_zmM_0;

        // initializing argument 'pv_api_op_mCB'
        ivd_ctl_getbufinfo_op_t pv_api_op_mCB_0;

        *(uint32_t*)((uint64_t)&pv_api_op_mCB_0 + 0) = 532; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_op_mCB_0 + 8) = 0 /* DEAD */; /* u4_num_disp_bufs */
        ivd_ctl_getbufinfo_op_t *pv_api_op_mCB_1 = &pv_api_op_mCB_0;

        dep_1062 = impeg2d_api_function(dep_1086, pv_api_ip_zmM_1, pv_api_op_mCB_1); /* vertex #8 */
        dep_1111_8 = *(uint32_t*)((uint64_t)&pv_api_op_mCB_0 + 8);	// Dependence family #1111_8 definition

    //}


    /* * * function pool #9 * * */
    //{
        // initializing argument 'pv_api_ip_Ish'
        ivd_set_display_frame_ip_t pv_api_ip_Ish_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_Ish_0 + 0) = 49680; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_Ish_0 + 4) = 9; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_Ish_0 + 8) = dep_1111_8; /* num_disp_bufs */

        for (uint64_t i_0=0; i_0<64; ++i_0) {
        }

        ivd_set_display_frame_ip_t *pv_api_ip_Ish_1 = &pv_api_ip_Ish_0;

        // initializing argument 'pv_api_op_VGX'
        ivd_set_display_frame_op_t pv_api_op_VGX_0;

        *(uint32_t*)((uint64_t)&pv_api_op_VGX_0 + 0) = 8; /* u4_size */
        ivd_set_display_frame_op_t *pv_api_op_VGX_1 = &pv_api_op_VGX_0;

        dep_1062 = impeg2d_api_function(dep_1086, pv_api_ip_Ish_1, pv_api_op_VGX_1); /* vertex #9 */

    //}


    /* * * function pool #10 * * */
    //{
        // initializing argument 'pv_api_ip_cZj'
        impeg2d_ctl_get_frame_dimensions_ip_t pv_api_ip_cZj_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_cZj_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_cZj_0 + 4) = 5; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_cZj_0 + 8) = 263; /* e_sub_cmd */
        impeg2d_ctl_get_frame_dimensions_ip_t *pv_api_ip_cZj_1 = &pv_api_ip_cZj_0;

        // initializing argument 'pv_api_op_EZd'
        impeg2d_ctl_get_frame_dimensions_op_t pv_api_op_EZd_0;

        *(uint32_t*)((uint64_t)&pv_api_op_EZd_0 + 0) = 80; /* u4_size */
        impeg2d_ctl_get_frame_dimensions_op_t *pv_api_op_EZd_1 = &pv_api_op_EZd_0;

        dep_1062 = impeg2d_api_function(dep_1086, pv_api_ip_cZj_1, pv_api_op_EZd_1); /* vertex #10 */

    //}


    /* * * function pool #11 * * */
    //{
        // initializing argument 'pv_api_ip_vVl'
        impeg2d_ctl_get_seq_info_ip_t pv_api_ip_vVl_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_vVl_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_vVl_0 + 4) = 5; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_vVl_0 + 8) = 264; /* e_sub_cmd */
        impeg2d_ctl_get_seq_info_ip_t *pv_api_ip_vVl_1 = &pv_api_ip_vVl_0;

        // initializing argument 'pv_api_op_vNV'
        impeg2d_ctl_get_seq_info_op_t pv_api_op_vNV_0;

        *(uint32_t*)((uint64_t)&pv_api_op_vNV_0 + 0) = 20; /* u4_size */
        impeg2d_ctl_get_seq_info_op_t *pv_api_op_vNV_1 = &pv_api_op_vNV_0;

        dep_1062 = impeg2d_api_function(dep_1086, pv_api_ip_vVl_1, pv_api_op_vNV_1); /* vertex #11 */

    //}


    /* * * function pool #12 * * */
    //{
        // initializing argument 'pv_api_ip_uok'
        ivd_ctl_set_config_ip_t pv_api_ip_uok_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_uok_0 + 0) = 28; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_uok_0 + 4) = 5; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_uok_0 + 8) = 1; /* e_sub_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_uok_0 + 12) = 0; /* e_vid_dec_mode */
        *(uint32_t*)((uint64_t)&pv_api_ip_uok_0 + 16) = 0; /* u4_disp_wd */
        *(uint32_t*)((uint64_t)&pv_api_ip_uok_0 + 20) = 2147483647; /* e_frm_skip_mode */
        *(uint32_t*)((uint64_t)&pv_api_ip_uok_0 + 24) = 0; /* e_frm_out_mode */
        ivd_ctl_set_config_ip_t *pv_api_ip_uok_1 = &pv_api_ip_uok_0;

        // initializing argument 'pv_api_op_Zjn'
        ivd_ctl_set_config_op_t pv_api_op_Zjn_0;

        *(uint32_t*)((uint64_t)&pv_api_op_Zjn_0 + 0) = 8; /* u4_size */
        ivd_ctl_set_config_op_t *pv_api_op_Zjn_1 = &pv_api_op_Zjn_0;

        dep_1062 = impeg2d_api_function(dep_1086, pv_api_ip_uok_1, pv_api_op_Zjn_1); /* vertex #12 */

    //}


    /* * * function pool #13 * * */
    //{
        // initializing argument 'pv_api_ip_HiV'
        ivd_ctl_getversioninfo_ip_t pv_api_ip_HiV_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_HiV_0 + 0) = 32; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_HiV_0 + 4) = 5; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_HiV_0 + 8) = 6; /* e_sub_cmd */

        for (uint64_t i_0=0; i_0<512; ++i_0) {
            v_pdZ[i_0] = 0 /* WO */;
        }

        *(uint8_t**)((uint64_t)&pv_api_ip_HiV_0 + 16) = v_pdZ; /* pv_version_buffer */
        *(uint32_t*)((uint64_t)&pv_api_ip_HiV_0 + 24) = 512; /* u4_version_buffer_size */
        ivd_ctl_getversioninfo_ip_t *pv_api_ip_HiV_1 = &pv_api_ip_HiV_0;

        // initializing argument 'pv_api_op_IVw'
        ivd_ctl_getversioninfo_op_t pv_api_op_IVw_0;

        *(uint32_t*)((uint64_t)&pv_api_op_IVw_0 + 0) = 8; /* u4_size */
        ivd_ctl_getversioninfo_op_t *pv_api_op_IVw_1 = &pv_api_op_IVw_0;

        impeg2d_api_function(*dep_1086, pv_api_ip_HiV_1, pv_api_op_IVw_1); /* vertex #17 */

    //}


    /* * * function pool #14 * * */
    //{
        // initializing argument 'pv_api_ip_knT'
        ivd_video_decode_ip_t pv_api_ip_knT_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_knT_0 + 0) = 800; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_knT_0 + 4) = 6; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_knT_0 + 8) = 0; /* u4_ts */
        *(uint32_t*)((uint64_t)&pv_api_ip_knT_0 + 12) = buflen; /* u4_num_Bytes */

        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            v_rjU[i_0] = E.buf_eat1();
        }

        *(uint8_t**)((uint64_t)&pv_api_ip_knT_0 + 16) = (uint8_t*)v_rjU; /* pv_stream_buffer */
        *(uint32_t*)((uint64_t)&pv_api_ip_knT_0 + 24) = dep_1098_16; /* u4_num_bufs */

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            for (uint64_t i_1=0; i_1<buflen; ++i_1) {
                v_rHg[i_0][i_1] = 0;
            }
            *(uint8_t**)((uint64_t)&pv_api_ip_knT_0 + 32 + i_0*sizeof(uint8_t)) = (uint8_t*)v_rHg[i_0]; /* pu1_bufs */
        }


        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint32_t*)((uint64_t)&pv_api_ip_knT_0 + 544 + i_0*sizeof(uint32_t)) = dep_1098_276[i_0]; /* u4_min_out_buf_size */
        }


        ivd_video_decode_ip_t *pv_api_ip_knT_1 = &pv_api_ip_knT_0;

        // initializing argument 'pv_api_op_uVJ'
        ivd_video_decode_op_t pv_api_op_uVJ_0;

        *(uint32_t*)((uint64_t)&pv_api_op_uVJ_0 + 0) = 136; /* u4_size */

        ivd_video_decode_op_t *pv_api_op_uVJ_1 = &pv_api_op_uVJ_0;

        dep_1062 = impeg2d_api_function(dep_1086, pv_api_ip_knT_1, pv_api_op_uVJ_1); /* vertex #13 */

    //}


    /* * * function pool #15 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    
        // initializing argument 'pv_api_ip_xyr'
        ivd_ctl_flush_ip_t pv_api_ip_xyr_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_xyr_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_xyr_0 + 4) = 5; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_xyr_0 + 8) = 4; /* e_sub_cmd */
        ivd_ctl_flush_ip_t *pv_api_ip_xyr_1 = &pv_api_ip_xyr_0;

        // initializing argument 'pv_api_op_BEt'
        ivd_ctl_flush_op_t pv_api_op_BEt_0;

        *(uint32_t*)((uint64_t)&pv_api_op_BEt_0 + 0) = 8; /* u4_size */
        ivd_ctl_flush_op_t *pv_api_op_BEt_1 = &pv_api_op_BEt_0;


        // initializing argument 'pv_api_ip_zGh'
        ivd_ctl_flush_ip_t pv_api_ip_zGh_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_zGh_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_zGh_0 + 4) = 5; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_zGh_0 + 8) = 4; /* e_sub_cmd */
        ivd_ctl_flush_ip_t *pv_api_ip_zGh_1 = &pv_api_ip_zGh_0;

        // initializing argument 'pv_api_op_Vjq'
        ivd_ctl_flush_op_t pv_api_op_Vjq_0;

        *(uint32_t*)((uint64_t)&pv_api_op_Vjq_0 + 0) = 8; /* u4_size */
        ivd_ctl_flush_op_t *pv_api_op_Vjq_1 = &pv_api_op_Vjq_0;



        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_1048 = impeg2d_api_function(&dep_1086, pv_api_ip_xyr_1, pv_api_op_BEt_1); /* vertex #22 */
            }

            else if (perm[i] == 1) {
                dep_1048 = impeg2d_api_function(&dep_1086, pv_api_ip_zGh_1, pv_api_op_Vjq_1); /* vertex #26 */
            }

        }
    //}



    /* * * function pool #16 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    
        // initializing argument 'pv_api_ip_TFg'
        ivd_video_decode_ip_t pv_api_ip_TFg_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_TFg_0 + 0) = 800; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_TFg_0 + 4) = 6; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_TFg_0 + 8) = 0 /* DEAD */; /* u4_ts */
        *(uint32_t*)((uint64_t)&pv_api_ip_TFg_0 + 12) = 0 /* DEAD */; /* u4_num_Bytes */

        uint8_t v_cmg_0 = 0 /* DEAD */;
        *(uint8_t**)((uint64_t)&pv_api_ip_TFg_0 + 16) = &v_cmg_0; /* pv_stream_buffer */
        *(uint32_t*)((uint64_t)&pv_api_ip_TFg_0 + 24) = 0 /* DEAD */; /* u4_num_bufs */

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            v_RQd_0[i_0] = 0 /* DEAD */;
            v_RQd_1[i_0] = &v_RQd_0[i_0];
        }

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint8_t**)((uint64_t)&pv_api_ip_TFg_0 + 32 + i_0*sizeof(uint8_t)) = v_RQd_1[i_0]; /* pu1_bufs */
        }


        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint32_t*)((uint64_t)&pv_api_ip_TFg_0 + 544 + i_0*sizeof(uint32_t)) = buflen; /* u4_min_out_buf_size */
        }


        ivd_video_decode_ip_t *pv_api_ip_TFg_1 = &pv_api_ip_TFg_0;

        // initializing argument 'pv_api_op_vbN'
        ivd_video_decode_op_t pv_api_op_vbN_0;

        *(uint32_t*)((uint64_t)&pv_api_op_vbN_0 + 0) = 136; /* u4_size */

        ivd_video_decode_op_t *pv_api_op_vbN_1 = &pv_api_op_vbN_0;


        // initializing argument 'pv_api_ip_ViJ'
        ivd_video_decode_ip_t pv_api_ip_ViJ_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_ViJ_0 + 0) = 800; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_ViJ_0 + 4) = 6; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_ViJ_0 + 8) = 0 /* DEAD */; /* u4_ts */
        *(uint32_t*)((uint64_t)&pv_api_ip_ViJ_0 + 12) = 0 /* DEAD */; /* u4_num_Bytes */

        uint8_t v_rmK_0 = 0 /* DEAD */;
        *(uint8_t**)((uint64_t)&pv_api_ip_ViJ_0 + 16) = &v_rmK_0; /* pv_stream_buffer */
        *(uint32_t*)((uint64_t)&pv_api_ip_ViJ_0 + 24) = 0 /* DEAD */; /* u4_num_bufs */

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            v_ajZ_0[i_0] = 0 /* DEAD */;
            v_ajZ_1[i_0] = &v_ajZ_0[i_0];
        }

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint8_t**)((uint64_t)&pv_api_ip_ViJ_0 + 32 + i_0*sizeof(uint8_t)) = v_ajZ_1[i_0]; /* pu1_bufs */
        }


        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint32_t*)((uint64_t)&pv_api_ip_ViJ_0 + 544 + i_0*sizeof(uint32_t)) = buflen; /* u4_min_out_buf_size */
        }


        ivd_video_decode_ip_t *pv_api_ip_ViJ_1 = &pv_api_ip_ViJ_0;

        // initializing argument 'pv_api_op_WQJ'
        ivd_video_decode_op_t pv_api_op_WQJ_0;

        *(uint32_t*)((uint64_t)&pv_api_op_WQJ_0 + 0) = 136; /* u4_size */

        ivd_video_decode_op_t *pv_api_op_WQJ_1 = &pv_api_op_WQJ_0;



        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_1048 = impeg2d_api_function(&dep_1086, pv_api_ip_TFg_1, pv_api_op_vbN_1); /* vertex #23 */
            }

            else if (perm[i] == 1) {
                dep_1048 = impeg2d_api_function(&dep_1086, pv_api_ip_ViJ_1, pv_api_op_WQJ_1); /* vertex #27 */
            }

        }
    //}



    /* * * function pool #17 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    
        // initializing argument 'pv_api_ip_fZd'
        ivd_rel_display_frame_ip_t pv_api_ip_fZd_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_fZd_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_fZd_0 + 4) = 8; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_fZd_0 + 8) = 0 /* DEAD */; /* u4_disp_buf_id */
        ivd_rel_display_frame_ip_t *pv_api_ip_fZd_1 = &pv_api_ip_fZd_0;

        // initializing argument 'pv_api_op_uxW'
        ivd_rel_display_frame_op_t pv_api_op_uxW_0;

        *(uint32_t*)((uint64_t)&pv_api_op_uxW_0 + 0) = 8; /* u4_size */
        ivd_rel_display_frame_op_t *pv_api_op_uxW_1 = &pv_api_op_uxW_0;


        // initializing argument 'pv_api_ip_pWQ'
        ivd_rel_display_frame_ip_t pv_api_ip_pWQ_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_pWQ_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_pWQ_0 + 4) = 8; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_pWQ_0 + 8) = 0 /* DEAD */; /* u4_disp_buf_id */
        ivd_rel_display_frame_ip_t *pv_api_ip_pWQ_1 = &pv_api_ip_pWQ_0;

        // initializing argument 'pv_api_op_HmG'
        ivd_rel_display_frame_op_t pv_api_op_HmG_0;

        *(uint32_t*)((uint64_t)&pv_api_op_HmG_0 + 0) = 8; /* u4_size */
        ivd_rel_display_frame_op_t *pv_api_op_HmG_1 = &pv_api_op_HmG_0;



        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                impeg2d_api_function(*dep_1086, pv_api_ip_fZd_1, pv_api_op_uxW_1); /* vertex #24 */
            }

            else if (perm[i] == 1) {
                impeg2d_api_function(*dep_1086, pv_api_ip_pWQ_1, pv_api_op_HmG_1); /* vertex #28 */
            }

        }
    //}



    /* * * function pool #18 * * */
    //{
        // initializing argument 'pv_api_ip_Wsi'
        ivd_ctl_reset_ip_t pv_api_ip_Wsi_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_Wsi_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_Wsi_0 + 4) = 5; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_Wsi_0 + 8) = 2; /* e_sub_cmd */
        ivd_ctl_reset_ip_t *pv_api_ip_Wsi_1 = &pv_api_ip_Wsi_0;

        // initializing argument 'pv_api_op_NYu'
        ivd_ctl_reset_op_t pv_api_op_NYu_0;

        *(uint32_t*)((uint64_t)&pv_api_op_NYu_0 + 0) = 8; /* u4_size */
        ivd_ctl_reset_op_t *pv_api_op_NYu_1 = &pv_api_op_NYu_0;

        dep_1062 = impeg2d_api_function(dep_1086, pv_api_ip_Wsi_1, pv_api_op_NYu_1); /* vertex #25 */

    //}


    /* * * function pool #19 * * */
    //{
        // initializing argument 'pv_api_ip_VUP'
        impeg2d_ctl_set_num_cores_ip_t pv_api_ip_VUP_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_VUP_0 + 0) = 16; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_VUP_0 + 4) = 5; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_VUP_0 + 8) = 7; /* e_sub_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_VUP_0 + 12) = 1; /* u4_num_cores */
        impeg2d_ctl_set_num_cores_ip_t *pv_api_ip_VUP_1 = &pv_api_ip_VUP_0;

        // initializing argument 'pv_api_op_Rks'
        impeg2d_ctl_set_num_cores_op_t pv_api_op_Rks_0;

        *(uint32_t*)((uint64_t)&pv_api_op_Rks_0 + 0) = 8; /* u4_size */
        impeg2d_ctl_set_num_cores_op_t *pv_api_op_Rks_1 = &pv_api_op_Rks_0;

        dep_1062 = impeg2d_api_function(dep_1086, pv_api_ip_VUP_1, pv_api_op_Rks_1); /* vertex #14 */

    //}


    /* * * function pool #20 * * */
    //{
        // initializing argument 'pv_api_ip_dsM'
        impeg2d_ctl_set_processor_ip_t pv_api_ip_dsM_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_dsM_0 + 0) = 24; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_dsM_0 + 4) = 5; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_dsM_0 + 8) = 8; /* e_sub_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_dsM_0 + 12) = 1; /* u4_arch */
        *(uint32_t*)((uint64_t)&pv_api_ip_dsM_0 + 16) = 0; /* u4_soc */
        impeg2d_ctl_set_processor_ip_t *pv_api_ip_dsM_1 = &pv_api_ip_dsM_0;

        // initializing argument 'pv_api_op_YLG'
        impeg2d_ctl_set_processor_op_t pv_api_op_YLG_0;

        *(uint32_t*)((uint64_t)&pv_api_op_YLG_0 + 0) = 8; /* u4_size */
        impeg2d_ctl_set_processor_op_t *pv_api_op_YLG_1 = &pv_api_op_YLG_0;

        dep_1062 = impeg2d_api_function(dep_1086, pv_api_ip_dsM_1, pv_api_op_YLG_1); /* vertex #15 */

    //}


    /* * * function pool #21 * * */
    //{
        // initializing argument 'pv_api_ip_Soc'
        ivd_rel_display_frame_ip_t pv_api_ip_Soc_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_Soc_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_Soc_0 + 4) = 8; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_Soc_0 + 8) = 0 /* DEAD */; /* u4_disp_buf_id */
        ivd_rel_display_frame_ip_t *pv_api_ip_Soc_1 = &pv_api_ip_Soc_0;

        // initializing argument 'pv_api_op_icR'
        ivd_rel_display_frame_op_t pv_api_op_icR_0;

        *(uint32_t*)((uint64_t)&pv_api_op_icR_0 + 0) = 8; /* u4_size */
        ivd_rel_display_frame_op_t *pv_api_op_icR_1 = &pv_api_op_icR_0;

        impeg2d_api_function(*dep_1086, pv_api_ip_Soc_1, pv_api_op_icR_1); /* vertex #29 */

    //}


    /* * * function pool #22 * * */
    //{
        // initializing argument 'pv_api_ip_HvU'
        ivd_rel_display_frame_ip_t pv_api_ip_HvU_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_HvU_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_HvU_0 + 4) = 8; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_HvU_0 + 8) = 0 /* DEAD */; /* u4_disp_buf_id */
        ivd_rel_display_frame_ip_t *pv_api_ip_HvU_1 = &pv_api_ip_HvU_0;

        // initializing argument 'pv_api_op_PmE'
        ivd_rel_display_frame_op_t pv_api_op_PmE_0;

        *(uint32_t*)((uint64_t)&pv_api_op_PmE_0 + 0) = 8; /* u4_size */
        ivd_rel_display_frame_op_t *pv_api_op_PmE_1 = &pv_api_op_PmE_0;

        impeg2d_api_function(*dep_1086, pv_api_ip_HvU_1, pv_api_op_PmE_1); /* vertex #21 */

    //}


    /* * * function pool #23 * * */
    //{
        // initializing argument 'pv_api_ip_prY'
        ivd_ctl_flush_ip_t pv_api_ip_prY_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_prY_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_prY_0 + 4) = 5; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_prY_0 + 8) = 4; /* e_sub_cmd */
        ivd_ctl_flush_ip_t *pv_api_ip_prY_1 = &pv_api_ip_prY_0;

        // initializing argument 'pv_api_op_Ybh'
        ivd_ctl_flush_op_t pv_api_op_Ybh_0;

        *(uint32_t*)((uint64_t)&pv_api_op_Ybh_0 + 0) = 8; /* u4_size */
        ivd_ctl_flush_op_t *pv_api_op_Ybh_1 = &pv_api_op_Ybh_0;

        dep_1048 = impeg2d_api_function(&dep_1086, pv_api_ip_prY_1, pv_api_op_Ybh_1); /* vertex #18 */

    //}


    /* * * function pool #24 * * */
    //{
        // initializing argument 'pv_api_ip_eDv'
        ivd_video_decode_ip_t pv_api_ip_eDv_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_eDv_0 + 0) = 800; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_eDv_0 + 4) = 6; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_eDv_0 + 8) = 0 /* DEAD */; /* u4_ts */
        *(uint32_t*)((uint64_t)&pv_api_ip_eDv_0 + 12) = 0 /* DEAD */; /* u4_num_Bytes */

        uint8_t v_SvW_0 = 0 /* DEAD */;
        *(uint8_t**)((uint64_t)&pv_api_ip_eDv_0 + 16) = &v_SvW_0; /* pv_stream_buffer */
        *(uint32_t*)((uint64_t)&pv_api_ip_eDv_0 + 24) = 0 /* DEAD */; /* u4_num_bufs */

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            v_cNq_0[i_0] = 0 /* DEAD */;
            v_cNq_1[i_0] = &v_cNq_0[i_0];
        }

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint8_t**)((uint64_t)&pv_api_ip_eDv_0 + 32 + i_0*sizeof(uint8_t)) = v_cNq_1[i_0]; /* pu1_bufs */
        }


        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint32_t*)((uint64_t)&pv_api_ip_eDv_0 + 544 + i_0*sizeof(uint32_t)) = buflen; /* u4_min_out_buf_size */
        }


        ivd_video_decode_ip_t *pv_api_ip_eDv_1 = &pv_api_ip_eDv_0;

        // initializing argument 'pv_api_op_mnz'
        ivd_video_decode_op_t pv_api_op_mnz_0;

        *(uint32_t*)((uint64_t)&pv_api_op_mnz_0 + 0) = 136; /* u4_size */

        ivd_video_decode_op_t *pv_api_op_mnz_1 = &pv_api_op_mnz_0;

        dep_1048 = impeg2d_api_function(&dep_1086, pv_api_ip_eDv_1, pv_api_op_mnz_1); /* vertex #19 */

    //}


    /* * * function pool #25 * * */
    //{
        // initializing argument 'pv_api_ip_Eya'
        ivd_rel_display_frame_ip_t pv_api_ip_Eya_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_Eya_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_Eya_0 + 4) = 8; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_Eya_0 + 8) = 0 /* DEAD */; /* u4_disp_buf_id */
        ivd_rel_display_frame_ip_t *pv_api_ip_Eya_1 = &pv_api_ip_Eya_0;

        // initializing argument 'pv_api_op_YmG'
        ivd_rel_display_frame_op_t pv_api_op_YmG_0;

        *(uint32_t*)((uint64_t)&pv_api_op_YmG_0 + 0) = 8; /* u4_size */
        ivd_rel_display_frame_op_t *pv_api_op_YmG_1 = &pv_api_op_YmG_0;

        impeg2d_api_function(*dep_1086, pv_api_ip_Eya_1, pv_api_op_YmG_1); /* vertex #20 */

    //}


    /* * * function pool #26 * * */
    //{
        // initializing argument 'pv_api_ip_OYp'
        iv_retrieve_mem_rec_ip_t pv_api_ip_OYp_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_OYp_0 + 0) = 16; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_OYp_0 + 4) = 2; /* e_cmd */

        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            v_KlJ[i_0];

        }

        *(iv_mem_rec_t**)((uint64_t)&pv_api_ip_OYp_0 + 8) = (iv_mem_rec_t*)v_KlJ;
        iv_retrieve_mem_rec_ip_t *pv_api_ip_OYp_1 = &pv_api_ip_OYp_0;

        // initializing argument 'pv_api_op_GSi'
        iv_retrieve_mem_rec_op_t pv_api_op_GSi_0;

        *(uint32_t*)((uint64_t)&pv_api_op_GSi_0 + 0) = 12; /* u4_size */
        iv_retrieve_mem_rec_op_t *pv_api_op_GSi_1 = &pv_api_op_GSi_0;

        dep_1062 = impeg2d_api_function(dep_1086, pv_api_ip_OYp_1, pv_api_op_GSi_1); /* vertex #16 */

    //}




    return 0;
}

// ------------------------------------------------------------------------------------------------
