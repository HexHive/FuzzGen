// ------------------------------------------------------------------------------------------------
/*
 * Copyright (C) 2017 The Android Open Source Project
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
 * FuzzGen - The Automatic Fuzzer Generator
 * Version: v3
 *
 * Target Library: external/libavc
 * Build Options: analysis=deep; arch=x64; external=yes; root-all=no; permute=yes; 
 *                failure=yes; coalesce=yes; progressive=no; max-depth=4; seed=31337;
 *                min-buflen=32; max-buflen=4096;
 *
 * Issues: -
 *
 * ~~~ THIS FILE HAS BEEN GENERATED AUTOMATICALLY BY *FUZZGEN* AT: 29-11-2018 16:18:49 CET ~~~
 *
 */
// ------------------------------------------------------------------------------------------------
#include <cstdint>
#include <iostream>
#include <cassert>
#include <math.h>

/* headers for library includes */
#include "ih264_typedefs.h"
#include "ih264d.h"
#include "iv.h"
#include "ivd.h"


// ------------------------------------------------------------------------------------------------
using namespace std;

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
const int32_t v_sca[] = {40, 40};
const int32_t v_QMR[] = {1, 5, 9, 11, 12, 11};
const int64_t v_MQT[] = {0, 0};
const int32_t v_JFq[] = {16, 16};
const int32_t v_pCl[] = {24, 24};
const int32_t v_qfZ[] = {0, 4, 1};
const int32_t v_glt[] = {0, 0};
const int32_t v_Fwh[] = {8, 8};
const int32_t v_QhN[] = {24, 800};
const int64_t v_aYb[] = {28, 28};
const int64_t v_IIB[] = {7, 7};
const int64_t v_pKb[] = {1, 1};
const int64_t v_bZp[] = {1, 1};
const int64_t v_zmM[] = {0, 0};
const int64_t v_TmB[] = {2147483647, 2147483647};
const int64_t v_Lps[] = {0, 0};
const int64_t v_wZC[] = {8, 8};
const int32_t v_brm[] = {24, 800};
const int64_t v_FkC[] = {0, 0};
const int32_t v_Tjq[] = {80, 80};
const int32_t v_knT[] = {12, 12};
const int32_t v_jtr[] = {64, 64};
const int64_t v_Sva[] = {28, 28};
const int64_t v_pIj[] = {7, 7};
const int64_t v_BnJ[] = {1, 1};
const int64_t v_Mhi[] = {1, 0};
const int64_t v_fCM[] = {0, 0};
const int64_t v_pRn[] = {2147483647, 2147483647};
const int64_t v_BEt[] = {0, 0};
const int64_t v_zGh[] = {8, 8};
const int32_t v_vbN[] = {24, 800};
const int64_t v_Smt[] = {0, 0};
const int64_t v_qop[] = {12, 12};
const int64_t v_xTr[] = {7, 7};
const int64_t v_fZd[] = {4, 4};
const int64_t v_jDZ[] = {8, 8};
const int32_t v_pWQ[] = {24, 800};
const int64_t v_KsJ[] = {12, 12};
const int64_t v_zZT[] = {10, 10};
const int64_t v_SwQ[] = {8, 8};
const int64_t v_zsb[] = {16, 16};
const int64_t v_Pji[] = {7, 7};
const int64_t v_icR[] = {7, 7};
const int64_t v_Xzj[] = {1, 1};
const int64_t v_gNd[] = {8, 8};
const int32_t v_YOk[] = {24, 24};
const int32_t v_kci[] = {0, 4, 1};
const int32_t v_BSG[] = {0, 0};
const int32_t v_sZh[] = {8, 8};
const int64_t v_SsB[] = {12, 12};
const int64_t v_aVX[] = {10, 10};
const int64_t v_AaO[] = {8, 8};
const int64_t v_okJ[] = {12, 12};
const int64_t v_Eya[] = {10, 10};
const int64_t v_YmG[] = {8, 8};
const int64_t v_cCN[] = {12, 12};
const int64_t v_KlJ[] = {7, 7};
const int64_t v_zTW[] = {4, 4};
const int64_t v_Ymt[] = {8, 8};
const int32_t v_TyA[] = {24, 800};
const int64_t v_fEl[] = {12, 12};
const int64_t v_aOk[] = {10, 10};
const int64_t v_fbg[] = {8, 8};


/* global variables */
uint8_t *perm;
uint8_t* dep_175_8;
uint32_t dep_150;
iv_obj_t *dep_173;
uint32_t dep_133;
uint8_t v_iak_0[64];
uint8_t *v_iak_1[64];
uint8_t v_yFW[4096];
uint32_t dep_190_8;
uint32_t dep_190_16;
uint32_t dep_190_276[64];
uint8_t v_KPJ[512];
uint8_t v_Qrr[4096];
uint8_t v_MqW_0[64];
uint8_t *v_MqW_1[64];
uint8_t v_HeU_0[64];
uint8_t *v_HeU_1[64];
uint8_t v_stI_0[64];
uint8_t *v_stI_1[64];


size_t buflen = 32; /* adaptable buffer length */
size_t nbufs = 2; /* total number of buffers */
size_t ninp  = 328; /* total number of other input bytes */


/* function declarations (used by function pointers), if any */
uint8_t* ih264a_aligned_malloc(uint8_t* p0, uint32_t p1, uint32_t p2) {
    return (uint8_t*) memalign(p1, p2);

}

void ih264a_aligned_free(uint8_t* p0, uint8_t* p1) {
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
            data(data), size(size), delimiter(size-1 - ninp), bwctr(size-1), fwctr(0) { }


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
    if (size < 392 || size > 8520) return 0;

    /* all variables contain 3 random letters, so E cannot redefined */
    EatData E(data, size, ninp);

    buflen = (size - ninp) / nbufs - 1;             // find length of each buffer


    /* * * function pool #0 * * */
    //{
        // initializing argument 'ps_handle_iWq'

        // initializing argument 'pv_api_ip_mCT'
        ih264d_create_ip_t pv_api_ip_mCT_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_mCT_0 + 0) = v_sca[E.eat1() % 2]; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_mCT_0 + 4) = 5; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_mCT_0 + 8) = v_QMR[E.eat1() % 6]; /* e_output_format */
        *(uint32_t*)((uint64_t)&pv_api_ip_mCT_0 + 12) = v_MQT[E.eat1() % 2]; /* u4_share_disp_buf */
        *(uint64_t*)((uint64_t)&pv_api_ip_mCT_0 + 16) = (uint64_t)ih264a_aligned_malloc; /* pf_aligned_alloc */
        *(uint64_t*)((uint64_t)&pv_api_ip_mCT_0 + 24) = (uint64_t)ih264a_aligned_free; /* pf_aligned_free */
        *(uint8_t**)((uint64_t)&pv_api_ip_mCT_0 + 32) = NULL; /* pv_mem_ctxt */

        ih264d_create_ip_t *pv_api_ip_mCT_1 = &pv_api_ip_mCT_0;

        // initializing argument 'pv_api_op_gPl'
        ih264d_create_op_t pv_api_op_gPl_0;

        *(uint32_t*)((uint64_t)&pv_api_op_gPl_0 + 0) = v_JFq[E.eat1() % 2]; /* u4_size */

        uint8_t v_MUJ_0 = E.eat1();
        *(uint8_t**)((uint64_t)&pv_api_op_gPl_0 + 8) = &v_MUJ_0; /* pv_handle */

        ih264d_create_op_t *pv_api_op_gPl_1 = &pv_api_op_gPl_0;

        dep_150 = ih264d_api_function(NULL, pv_api_ip_mCT_1, pv_api_op_gPl_1); /* vertex #0 */
        dep_175_8 = *(uint8_t**)((uint64_t)&pv_api_op_gPl_0 + 8);	// Dependence family #175_8 definition

    //}


    /* * * function pool #1 * * */
    //{
        // initializing argument 'ps_handle_ROo'
        iv_obj_t *ps_handle_ROo_0 = (iv_obj_t*)dep_175_8;

        *(uint32_t*)((uint64_t)ps_handle_ROo_0 + 0) = 24; /* u4_size */
        *(uint64_t*)((uint64_t)ps_handle_ROo_0 + 8) = (uint64_t)ih264d_api_function; /* pv_fxns */

        // Dependence family #173 Definition
        dep_173 = (iv_obj_t *)ps_handle_ROo_0;
        // initializing argument 'pv_api_ip_uft'
        ivd_ctl_set_config_ip_t pv_api_ip_uft_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_uft_0 + 0) = 28; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_uft_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_uft_0 + 8) = 1; /* e_sub_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_uft_0 + 12) = 1; /* e_vid_dec_mode */
        *(uint32_t*)((uint64_t)&pv_api_ip_uft_0 + 16) = 0; /* u4_disp_wd */
        *(uint32_t*)((uint64_t)&pv_api_ip_uft_0 + 20) = 2147483647; /* e_frm_skip_mode */
        *(uint32_t*)((uint64_t)&pv_api_ip_uft_0 + 24) = 0; /* e_frm_out_mode */
        ivd_ctl_set_config_ip_t *pv_api_ip_uft_1 = &pv_api_ip_uft_0;

        // initializing argument 'pv_api_op_AVt'
        ivd_ctl_set_config_op_t pv_api_op_AVt_0;

        *(uint32_t*)((uint64_t)&pv_api_op_AVt_0 + 0) = 8; /* u4_size */
        ivd_ctl_set_config_op_t *pv_api_op_AVt_1 = &pv_api_op_AVt_0;

        dep_150 = ih264d_api_function(dep_173, pv_api_ip_uft_1, pv_api_op_AVt_1); /* vertex #1 */

    //}


    /* * * function pool #2 * * */
    //{
        // initializing argument 'pv_api_ip_uAC'
        ih264d_ctl_set_num_cores_ip_t pv_api_ip_uAC_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_uAC_0 + 0) = 16; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_uAC_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_uAC_0 + 8) = 7; /* e_sub_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_uAC_0 + 12) = 1; /* u4_num_cores */
        ih264d_ctl_set_num_cores_ip_t *pv_api_ip_uAC_1 = &pv_api_ip_uAC_0;

        // initializing argument 'pv_api_op_HIl'
        ih264d_ctl_set_num_cores_op_t pv_api_op_HIl_0;

        *(uint32_t*)((uint64_t)&pv_api_op_HIl_0 + 0) = 8; /* u4_size */
        ih264d_ctl_set_num_cores_op_t *pv_api_op_HIl_1 = &pv_api_op_HIl_0;

        dep_150 = ih264d_api_function(dep_173, pv_api_ip_uAC_1, pv_api_op_HIl_1); /* vertex #2 */

    //}


    /* * * function pool #3 * * */
    //{
        // initializing argument 'pv_api_ip_GiF'
        ih264d_ctl_set_processor_ip_t pv_api_ip_GiF_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_GiF_0 + 0) = v_pCl[E.eat1() % 2]; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_GiF_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_GiF_0 + 8) = 8; /* e_sub_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_GiF_0 + 12) = v_qfZ[E.eat1() % 3]; /* u4_arch */
        *(uint32_t*)((uint64_t)&pv_api_ip_GiF_0 + 16) = v_glt[E.eat1() % 2]; /* u4_soc */
        ih264d_ctl_set_processor_ip_t *pv_api_ip_GiF_1 = &pv_api_ip_GiF_0;

        // initializing argument 'pv_api_op_mVo'
        ih264d_ctl_set_processor_op_t pv_api_op_mVo_0;

        *(uint32_t*)((uint64_t)&pv_api_op_mVo_0 + 0) = v_Fwh[E.eat1() % 2]; /* u4_size */
        ih264d_ctl_set_processor_op_t *pv_api_op_mVo_1 = &pv_api_op_mVo_0;

        dep_150 = ih264d_api_function(dep_173, pv_api_ip_GiF_1, pv_api_op_mVo_1); /* vertex #3 */

    //}


    /* * * function pool #4 * * */
    //{
        // initializing argument 'pv_api_ip_YRl'
        ivd_ctl_flush_ip_t pv_api_ip_YRl_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_YRl_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_YRl_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_YRl_0 + 8) = 4; /* e_sub_cmd */
        ivd_ctl_flush_ip_t *pv_api_ip_YRl_1 = &pv_api_ip_YRl_0;

        // initializing argument 'pv_api_op_cJx'
        ivd_ctl_flush_op_t pv_api_op_cJx_0;

        *(uint32_t*)((uint64_t)&pv_api_op_cJx_0 + 0) = 8; /* u4_size */
        ivd_ctl_flush_op_t *pv_api_op_cJx_1 = &pv_api_op_cJx_0;

        dep_133 = ih264d_api_function(dep_173, pv_api_ip_YRl_1, pv_api_op_cJx_1); /* vertex #15 */

    //}


    /* * * function pool #5 * * */
    //{
        // initializing argument 'pv_api_ip_pPO'
        ivd_video_decode_ip_t pv_api_ip_pPO_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_pPO_0 + 0) = v_QhN[E.eat1() % 2]; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_pPO_0 + 4) = 8; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_pPO_0 + 8) = 0; /* u4_ts */
        *(uint32_t*)((uint64_t)&pv_api_ip_pPO_0 + 12) = 0 /* DEAD */; /* u4_num_Bytes */

        uint8_t v_CDv_0 = 0 /* DEAD */;
        *(uint8_t**)((uint64_t)&pv_api_ip_pPO_0 + 16) = &v_CDv_0; /* pv_stream_buffer */
        *(uint32_t*)((uint64_t)&pv_api_ip_pPO_0 + 24) = 0 /* DEAD */; /* u4_num_bufs */

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            v_iak_0[i_0] = 0 /* DEAD */;
            v_iak_1[i_0] = &v_iak_0[i_0];
        }

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint8_t**)((uint64_t)&pv_api_ip_pPO_0 + 32 + i_0*sizeof(uint8_t)) = v_iak_1[i_0]; /* pu1_bufs */
        }


        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint32_t*)((uint64_t)&pv_api_ip_pPO_0 + 544 + i_0*sizeof(uint32_t)) = buflen; /* u4_min_out_buf_size */
        }


        ivd_video_decode_ip_t *pv_api_ip_pPO_1 = &pv_api_ip_pPO_0;

        // initializing argument 'pv_api_op_PxZ'
        ivd_video_decode_op_t pv_api_op_PxZ_0;

        *(uint32_t*)((uint64_t)&pv_api_op_PxZ_0 + 0) = 136; /* u4_size */

        ivd_video_decode_op_t *pv_api_op_PxZ_1 = &pv_api_op_PxZ_0;

        dep_133 = ih264d_api_function(dep_173, pv_api_ip_pPO_1, pv_api_op_PxZ_1); /* vertex #16 */

    //}


    /* * * function pool #6 * * */
    //{
        // initializing argument 'pv_api_ip_Wgb'
        ivd_rel_display_frame_ip_t pv_api_ip_Wgb_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_Wgb_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_Wgb_0 + 4) = 10; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_Wgb_0 + 8) = 0 /* DEAD */; /* u4_disp_buf_id */
        ivd_rel_display_frame_ip_t *pv_api_ip_Wgb_1 = &pv_api_ip_Wgb_0;

        // initializing argument 'pv_api_op_BTN'
        ivd_rel_display_frame_op_t pv_api_op_BTN_0;

        *(uint32_t*)((uint64_t)&pv_api_op_BTN_0 + 0) = 8; /* u4_size */
        ivd_rel_display_frame_op_t *pv_api_op_BTN_1 = &pv_api_op_BTN_0;

        ih264d_api_function(dep_173, pv_api_ip_Wgb_1, pv_api_op_BTN_1); /* vertex #17 */

    //}


    /* * * function pool #7 * * */
    //{
        // initializing argument 'pv_api_ip_wQE'
        ivd_ctl_set_config_ip_t pv_api_ip_wQE_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_wQE_0 + 0) = v_aYb[E.eat1() % 2]; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_wQE_0 + 4) = v_IIB[E.eat1() % 2]; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_wQE_0 + 8) = v_pKb[E.eat1() % 2]; /* e_sub_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_wQE_0 + 12) = v_bZp[E.eat1() % 2]; /* e_vid_dec_mode */
        *(uint32_t*)((uint64_t)&pv_api_ip_wQE_0 + 16) = v_zmM[E.eat1() % 2]; /* u4_disp_wd */
        *(uint32_t*)((uint64_t)&pv_api_ip_wQE_0 + 20) = v_TmB[E.eat1() % 2]; /* e_frm_skip_mode */
        *(uint32_t*)((uint64_t)&pv_api_ip_wQE_0 + 24) = v_Lps[E.eat1() % 2]; /* e_frm_out_mode */
        ivd_ctl_set_config_ip_t *pv_api_ip_wQE_1 = &pv_api_ip_wQE_0;

        // initializing argument 'pv_api_op_uRO'
        ivd_ctl_set_config_op_t pv_api_op_uRO_0;

        *(uint32_t*)((uint64_t)&pv_api_op_uRO_0 + 0) = v_wZC[E.eat1() % 2]; /* u4_size */
        ivd_ctl_set_config_op_t *pv_api_op_uRO_1 = &pv_api_op_uRO_0;

        dep_150 = ih264d_api_function(dep_173, pv_api_ip_wQE_1, pv_api_op_uRO_1); /* vertex #4 */

    //}


    /* * * function pool #8 * * */
    //{
        // initializing argument 'pv_api_ip_WAR'
        ivd_video_decode_ip_t pv_api_ip_WAR_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_WAR_0 + 0) = v_brm[E.eat1() % 2]; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_WAR_0 + 4) = 8; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_WAR_0 + 8) = v_FkC[E.eat1() % 2]; /* u4_ts */
        *(uint32_t*)((uint64_t)&pv_api_ip_WAR_0 + 12) = buflen; /* u4_num_Bytes */

        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            v_yFW[i_0] = E.buf_eat1();
        }

        *(uint8_t**)((uint64_t)&pv_api_ip_WAR_0 + 16) = (uint8_t*)v_yFW; /* pv_stream_buffer */

        ivd_video_decode_ip_t *pv_api_ip_WAR_1 = &pv_api_ip_WAR_0;

        // initializing argument 'pv_api_op_vze'
        ivd_video_decode_op_t pv_api_op_vze_0;

        *(uint32_t*)((uint64_t)&pv_api_op_vze_0 + 0) = 136; /* u4_size */

        ivd_video_decode_op_t *pv_api_op_vze_1 = &pv_api_op_vze_0;

        dep_150 = ih264d_api_function(dep_173, pv_api_ip_WAR_1, pv_api_op_vze_1); /* vertex #5 */

    //}


    /* * * function pool #9 * * */
    //{
        // initializing argument 'pv_api_ip_hsp'
        ivd_ctl_getbufinfo_ip_t pv_api_ip_hsp_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_hsp_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_hsp_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_hsp_0 + 8) = 5; /* e_sub_cmd */
        ivd_ctl_getbufinfo_ip_t *pv_api_ip_hsp_1 = &pv_api_ip_hsp_0;

        // initializing argument 'pv_api_op_Xap'
        ivd_ctl_getbufinfo_op_t pv_api_op_Xap_0;

        *(uint32_t*)((uint64_t)&pv_api_op_Xap_0 + 0) = 532; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_op_Xap_0 + 8) = E.eat4(); /* u4_num_disp_bufs */
        *(uint32_t*)((uint64_t)&pv_api_op_Xap_0 + 16) = E.eat4(); /* u4_min_num_out_bufs */

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint32_t*)((uint64_t)&pv_api_op_Xap_0 + 276 + i_0*sizeof(uint32_t)) = E.eat4(); /* u4_min_out_buf_size */
        }

        ivd_ctl_getbufinfo_op_t *pv_api_op_Xap_1 = &pv_api_op_Xap_0;

        dep_150 = ih264d_api_function(dep_173, pv_api_ip_hsp_1, pv_api_op_Xap_1); /* vertex #6 */
        dep_190_8 = *(uint32_t*)((uint64_t)&pv_api_op_Xap_0 + 8);	// Dependence family #190_8 definition

        dep_190_16 = *(uint32_t*)((uint64_t)&pv_api_op_Xap_0 + 16);	// Dependence family #190_16 definition

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            dep_190_276[i_0] = *(uint32_t*)((uint64_t)&pv_api_op_Xap_0 + 276 + i_0*sizeof(uint32_t));	// Dependence family #190_276 definition
        }


    //}


    /* * * function pool #10 * * */
    //{
        // initializing argument 'pv_api_ip_elf'
        ivd_set_display_frame_ip_t pv_api_ip_elf_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_elf_0 + 0) = 49680; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_elf_0 + 4) = 11; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_elf_0 + 8) = dep_190_8; /* num_disp_bufs */

        for (uint64_t i_0=0; i_0<64; ++i_0) {
        }

        ivd_set_display_frame_ip_t *pv_api_ip_elf_1 = &pv_api_ip_elf_0;

        // initializing argument 'pv_api_op_gGc'
        ivd_set_display_frame_op_t pv_api_op_gGc_0;

        *(uint32_t*)((uint64_t)&pv_api_op_gGc_0 + 0) = 8; /* u4_size */
        ivd_set_display_frame_op_t *pv_api_op_gGc_1 = &pv_api_op_gGc_0;

        dep_150 = ih264d_api_function(dep_173, pv_api_ip_elf_1, pv_api_op_gGc_1); /* vertex #7 */

    //}


    /* * * function pool #11 * * */
    //{
        // initializing argument 'pv_api_ip_cck'
        ih264d_ctl_get_frame_dimensions_ip_t pv_api_ip_cck_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_cck_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_cck_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_cck_0 + 8) = 263; /* e_sub_cmd */
        ih264d_ctl_get_frame_dimensions_ip_t *pv_api_ip_cck_1 = &pv_api_ip_cck_0;

        // initializing argument 'pv_api_op_pdZ'
        ih264d_ctl_get_frame_dimensions_op_t pv_api_op_pdZ_0;

        *(uint32_t*)((uint64_t)&pv_api_op_pdZ_0 + 0) = v_Tjq[E.eat1() % 2]; /* u4_size */
        ih264d_ctl_get_frame_dimensions_op_t *pv_api_op_pdZ_1 = &pv_api_op_pdZ_0;

        dep_150 = ih264d_api_function(dep_173, pv_api_ip_cck_1, pv_api_op_pdZ_1); /* vertex #8 */

    //}


    /* * * function pool #12 * * */
    //{
        // initializing argument 'pv_api_ip_Cvl'
        ih264d_ctl_get_vui_params_ip_t pv_api_ip_Cvl_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_Cvl_0 + 0) = v_knT[E.eat1() % 2]; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_Cvl_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_Cvl_0 + 8) = 264; /* e_sub_cmd */
        ih264d_ctl_get_vui_params_ip_t *pv_api_ip_Cvl_1 = &pv_api_ip_Cvl_0;

        // initializing argument 'pv_api_op_kOj'
        ih264d_ctl_get_vui_params_op_t pv_api_op_kOj_0;

        *(uint32_t*)((uint64_t)&pv_api_op_kOj_0 + 0) = v_jtr[E.eat1() % 2]; /* u4_size */
        ih264d_ctl_get_vui_params_op_t *pv_api_op_kOj_1 = &pv_api_op_kOj_0;

        dep_150 = ih264d_api_function(dep_173, pv_api_ip_Cvl_1, pv_api_op_kOj_1); /* vertex #9 */

    //}


    /* * * function pool #13 * * */
    //{
        // initializing argument 'pv_api_ip_CuK'
        ivd_ctl_set_config_ip_t pv_api_ip_CuK_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_CuK_0 + 0) = v_Sva[E.eat1() % 2]; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_CuK_0 + 4) = v_pIj[E.eat1() % 2]; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_CuK_0 + 8) = v_BnJ[E.eat1() % 2]; /* e_sub_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_CuK_0 + 12) = v_Mhi[E.eat1() % 2]; /* e_vid_dec_mode */
        *(uint32_t*)((uint64_t)&pv_api_ip_CuK_0 + 16) = v_fCM[E.eat1() % 2]; /* u4_disp_wd */
        *(uint32_t*)((uint64_t)&pv_api_ip_CuK_0 + 20) = v_pRn[E.eat1() % 2]; /* e_frm_skip_mode */
        *(uint32_t*)((uint64_t)&pv_api_ip_CuK_0 + 24) = v_BEt[E.eat1() % 2]; /* e_frm_out_mode */
        ivd_ctl_set_config_ip_t *pv_api_ip_CuK_1 = &pv_api_ip_CuK_0;

        // initializing argument 'pv_api_op_lWb'
        ivd_ctl_set_config_op_t pv_api_op_lWb_0;

        *(uint32_t*)((uint64_t)&pv_api_op_lWb_0 + 0) = v_zGh[E.eat1() % 2]; /* u4_size */
        ivd_ctl_set_config_op_t *pv_api_op_lWb_1 = &pv_api_op_lWb_0;

        dep_150 = ih264d_api_function(dep_173, pv_api_ip_CuK_1, pv_api_op_lWb_1); /* vertex #10 */

    //}


    /* * * function pool #14 * * */
    //{
        // initializing argument 'pv_api_ip_ncI'
        ih264d_ctl_degrade_ip_t pv_api_ip_ncI_0;

        ih264d_ctl_degrade_ip_t *pv_api_ip_ncI_1 = &pv_api_ip_ncI_0;

        // initializing argument 'pv_api_op_Vjq'
        ih264d_ctl_degrade_op_t pv_api_op_Vjq_0;

        ih264d_ctl_degrade_op_t *pv_api_op_Vjq_1 = &pv_api_op_Vjq_0;

        ih264d_api_function(dep_173, pv_api_ip_ncI_1, pv_api_op_Vjq_1); /* vertex #18 */

    //}


    /* * * function pool #15 * * */
    //{
        // initializing argument 'pv_api_ip_pjm'
        ivd_ctl_getversioninfo_ip_t pv_api_ip_pjm_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_pjm_0 + 0) = 32; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_pjm_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_pjm_0 + 8) = 6; /* e_sub_cmd */

        for (uint64_t i_0=0; i_0<512; ++i_0) {
            v_KPJ[i_0] = 0 /* WO */;
        }

        *(uint8_t**)((uint64_t)&pv_api_ip_pjm_0 + 16) = v_KPJ; /* pv_version_buffer */
        *(uint32_t*)((uint64_t)&pv_api_ip_pjm_0 + 24) = buflen; /* u4_version_buffer_size */
        ivd_ctl_getversioninfo_ip_t *pv_api_ip_pjm_1 = &pv_api_ip_pjm_0;

        // initializing argument 'pv_api_op_Ghq'
        ivd_ctl_getversioninfo_op_t pv_api_op_Ghq_0;

        *(uint32_t*)((uint64_t)&pv_api_op_Ghq_0 + 0) = 8; /* u4_size */
        ivd_ctl_getversioninfo_op_t *pv_api_op_Ghq_1 = &pv_api_op_Ghq_0;

        ih264d_api_function(dep_173, pv_api_ip_pjm_1, pv_api_op_Ghq_1); /* vertex #19 */

    //}


    /* * * function pool #16 * * */
    //{
        // initializing argument 'pv_api_ip_WdR'
        ivd_video_decode_ip_t pv_api_ip_WdR_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_WdR_0 + 0) = v_vbN[E.eat1() % 2]; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_WdR_0 + 4) = 8; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_WdR_0 + 8) = v_Smt[E.eat1() % 2]; /* u4_ts */
        *(uint32_t*)((uint64_t)&pv_api_ip_WdR_0 + 12) = buflen; /* u4_num_Bytes */

        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            v_Qrr[i_0] = E.buf_eat1();
        }

        *(uint8_t**)((uint64_t)&pv_api_ip_WdR_0 + 16) = (uint8_t*)v_Qrr; /* pv_stream_buffer */
        *(uint32_t*)((uint64_t)&pv_api_ip_WdR_0 + 24) = dep_190_16; /* u4_num_bufs */

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            v_MqW_0[i_0] = 0 /* DEAD */;
            v_MqW_1[i_0] = &v_MqW_0[i_0];
        }

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint8_t**)((uint64_t)&pv_api_ip_WdR_0 + 32 + i_0*sizeof(uint8_t)) = v_MqW_1[i_0]; /* pu1_bufs */
        }


        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint32_t*)((uint64_t)&pv_api_ip_WdR_0 + 544 + i_0*sizeof(uint32_t)) = dep_190_276[i_0]; /* u4_min_out_buf_size */
        }


        ivd_video_decode_ip_t *pv_api_ip_WdR_1 = &pv_api_ip_WdR_0;

        // initializing argument 'pv_api_op_wRs'
        ivd_video_decode_op_t pv_api_op_wRs_0;

        *(uint32_t*)((uint64_t)&pv_api_op_wRs_0 + 0) = 136; /* u4_size */

        ivd_video_decode_op_t *pv_api_op_wRs_1 = &pv_api_op_wRs_0;

        dep_150 = ih264d_api_function(dep_173, pv_api_ip_WdR_1, pv_api_op_wRs_1); /* vertex #11 */

    //}


    /* * * function pool #17 * * */
    //{
        // initializing argument 'pv_api_ip_WQJ'
        ivd_ctl_flush_ip_t pv_api_ip_WQJ_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_WQJ_0 + 0) = v_qop[E.eat1() % 2]; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_WQJ_0 + 4) = v_xTr[E.eat1() % 2]; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_WQJ_0 + 8) = v_fZd[E.eat1() % 2]; /* e_sub_cmd */
        ivd_ctl_flush_ip_t *pv_api_ip_WQJ_1 = &pv_api_ip_WQJ_0;

        // initializing argument 'pv_api_op_Bfy'
        ivd_ctl_flush_op_t pv_api_op_Bfy_0;

        *(uint32_t*)((uint64_t)&pv_api_op_Bfy_0 + 0) = v_jDZ[E.eat1() % 2]; /* u4_size */
        ivd_ctl_flush_op_t *pv_api_op_Bfy_1 = &pv_api_op_Bfy_0;

        dep_133 = ih264d_api_function(dep_173, pv_api_ip_WQJ_1, pv_api_op_Bfy_1); /* vertex #24 */

    //}


    /* * * function pool #18 * * */
    //{
        // initializing argument 'pv_api_ip_NtB'
        ivd_video_decode_ip_t pv_api_ip_NtB_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_NtB_0 + 0) = v_pWQ[E.eat1() % 2]; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_NtB_0 + 4) = 8; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_NtB_0 + 8) = 0; /* u4_ts */
        *(uint32_t*)((uint64_t)&pv_api_ip_NtB_0 + 12) = 0 /* DEAD */; /* u4_num_Bytes */

        uint8_t v_yBA_0 = 0 /* DEAD */;
        *(uint8_t**)((uint64_t)&pv_api_ip_NtB_0 + 16) = &v_yBA_0; /* pv_stream_buffer */
        *(uint32_t*)((uint64_t)&pv_api_ip_NtB_0 + 24) = 0 /* DEAD */; /* u4_num_bufs */

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            v_HeU_0[i_0] = 0 /* DEAD */;
            v_HeU_1[i_0] = &v_HeU_0[i_0];
        }

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint8_t**)((uint64_t)&pv_api_ip_NtB_0 + 32 + i_0*sizeof(uint8_t)) = v_HeU_1[i_0]; /* pu1_bufs */
        }


        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint32_t*)((uint64_t)&pv_api_ip_NtB_0 + 544 + i_0*sizeof(uint32_t)) = buflen; /* u4_min_out_buf_size */
        }


        ivd_video_decode_ip_t *pv_api_ip_NtB_1 = &pv_api_ip_NtB_0;

        // initializing argument 'pv_api_op_lCk'
        ivd_video_decode_op_t pv_api_op_lCk_0;

        *(uint32_t*)((uint64_t)&pv_api_op_lCk_0 + 0) = 136; /* u4_size */

        ivd_video_decode_op_t *pv_api_op_lCk_1 = &pv_api_op_lCk_0;

        dep_133 = ih264d_api_function(dep_173, pv_api_ip_NtB_1, pv_api_op_lCk_1); /* vertex #25 */

    //}


    /* * * function pool #19 * * */
    //{
        // initializing argument 'pv_api_ip_zYT'
        ivd_rel_display_frame_ip_t pv_api_ip_zYT_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_zYT_0 + 0) = v_KsJ[E.eat1() % 2]; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_zYT_0 + 4) = v_zZT[E.eat1() % 2]; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_zYT_0 + 8) = 0 /* DEAD */; /* u4_disp_buf_id */
        ivd_rel_display_frame_ip_t *pv_api_ip_zYT_1 = &pv_api_ip_zYT_0;

        // initializing argument 'pv_api_op_Rks'
        ivd_rel_display_frame_op_t pv_api_op_Rks_0;

        *(uint32_t*)((uint64_t)&pv_api_op_Rks_0 + 0) = v_SwQ[E.eat1() % 2]; /* u4_size */
        ivd_rel_display_frame_op_t *pv_api_op_Rks_1 = &pv_api_op_Rks_0;

        ih264d_api_function(dep_173, pv_api_ip_zYT_1, pv_api_op_Rks_1); /* vertex #26 */

    //}


    /* * * function pool #20 * * */
    //{
        // initializing argument 'pv_api_ip_uEf'
        ivd_ctl_reset_ip_t pv_api_ip_uEf_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_uEf_0 + 0) = 12; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_uEf_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_uEf_0 + 8) = 2; /* e_sub_cmd */
        ivd_ctl_reset_ip_t *pv_api_ip_uEf_1 = &pv_api_ip_uEf_0;

        // initializing argument 'pv_api_op_ezG'
        ivd_ctl_reset_op_t pv_api_op_ezG_0;

        *(uint32_t*)((uint64_t)&pv_api_op_ezG_0 + 0) = 8; /* u4_size */
        ivd_ctl_reset_op_t *pv_api_op_ezG_1 = &pv_api_op_ezG_0;

        dep_150 = ih264d_api_function(dep_173, pv_api_ip_uEf_1, pv_api_op_ezG_1); /* vertex #27 */

    //}


    /* * * function pool #21 * * */
    //{
        // initializing argument 'pv_api_ip_gUV'
        ih264d_ctl_set_num_cores_ip_t pv_api_ip_gUV_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_gUV_0 + 0) = v_zsb[E.eat1() % 2]; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_gUV_0 + 4) = v_Pji[E.eat1() % 2]; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_gUV_0 + 8) = v_icR[E.eat1() % 2]; /* e_sub_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_gUV_0 + 12) = v_Xzj[E.eat1() % 2]; /* u4_num_cores */
        ih264d_ctl_set_num_cores_ip_t *pv_api_ip_gUV_1 = &pv_api_ip_gUV_0;

        // initializing argument 'pv_api_op_HvU'
        ih264d_ctl_set_num_cores_op_t pv_api_op_HvU_0;

        *(uint32_t*)((uint64_t)&pv_api_op_HvU_0 + 0) = v_gNd[E.eat1() % 2]; /* u4_size */
        ih264d_ctl_set_num_cores_op_t *pv_api_op_HvU_1 = &pv_api_op_HvU_0;

        dep_150 = ih264d_api_function(dep_173, pv_api_ip_gUV_1, pv_api_op_HvU_1); /* vertex #12 */

    //}


    /* * * function pool #22 * * */
    //{
        // initializing argument 'pv_api_ip_PmE'
        ih264d_ctl_set_processor_ip_t pv_api_ip_PmE_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_PmE_0 + 0) = v_YOk[E.eat1() % 2]; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_PmE_0 + 4) = 7; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_PmE_0 + 8) = 8; /* e_sub_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_PmE_0 + 12) = v_kci[E.eat1() % 3]; /* u4_arch */
        *(uint32_t*)((uint64_t)&pv_api_ip_PmE_0 + 16) = v_BSG[E.eat1() % 2]; /* u4_soc */
        ih264d_ctl_set_processor_ip_t *pv_api_ip_PmE_1 = &pv_api_ip_PmE_0;

        // initializing argument 'pv_api_op_gsV'
        ih264d_ctl_set_processor_op_t pv_api_op_gsV_0;

        *(uint32_t*)((uint64_t)&pv_api_op_gsV_0 + 0) = v_sZh[E.eat1() % 2]; /* u4_size */
        ih264d_ctl_set_processor_op_t *pv_api_op_gsV_1 = &pv_api_op_gsV_0;

        dep_150 = ih264d_api_function(dep_173, pv_api_ip_PmE_1, pv_api_op_gsV_1); /* vertex #13 */

    //}


    /* * * function pool #23 * * */
    //{
        // initializing argument 'pv_api_ip_nKm'
        ivd_rel_display_frame_ip_t pv_api_ip_nKm_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_nKm_0 + 0) = v_SsB[E.eat1() % 2]; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_nKm_0 + 4) = v_aVX[E.eat1() % 2]; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_nKm_0 + 8) = 0 /* DEAD */; /* u4_disp_buf_id */
        ivd_rel_display_frame_ip_t *pv_api_ip_nKm_1 = &pv_api_ip_nKm_0;

        // initializing argument 'pv_api_op_vHR'
        ivd_rel_display_frame_op_t pv_api_op_vHR_0;

        *(uint32_t*)((uint64_t)&pv_api_op_vHR_0 + 0) = v_AaO[E.eat1() % 2]; /* u4_size */
        ivd_rel_display_frame_op_t *pv_api_op_vHR_1 = &pv_api_op_vHR_0;

        ih264d_api_function(dep_173, pv_api_ip_nKm_1, pv_api_op_vHR_1); /* vertex #28 */

    //}


    /* * * function pool #24 * * */
    //{
        // initializing argument 'pv_api_ip_orQ'
        ivd_rel_display_frame_ip_t pv_api_ip_orQ_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_orQ_0 + 0) = v_okJ[E.eat1() % 2]; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_orQ_0 + 4) = v_Eya[E.eat1() % 2]; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_orQ_0 + 8) = 0 /* DEAD */; /* u4_disp_buf_id */
        ivd_rel_display_frame_ip_t *pv_api_ip_orQ_1 = &pv_api_ip_orQ_0;

        // initializing argument 'pv_api_op_Hys'
        ivd_rel_display_frame_op_t pv_api_op_Hys_0;

        *(uint32_t*)((uint64_t)&pv_api_op_Hys_0 + 0) = v_YmG[E.eat1() % 2]; /* u4_size */
        ivd_rel_display_frame_op_t *pv_api_op_Hys_1 = &pv_api_op_Hys_0;

        ih264d_api_function(dep_173, pv_api_ip_orQ_1, pv_api_op_Hys_1); /* vertex #23 */

    //}


    /* * * function pool #25 * * */
    //{
        // initializing argument 'pv_api_ip_flv'
        ivd_ctl_flush_ip_t pv_api_ip_flv_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_flv_0 + 0) = v_cCN[E.eat1() % 2]; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_flv_0 + 4) = v_KlJ[E.eat1() % 2]; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_flv_0 + 8) = v_zTW[E.eat1() % 2]; /* e_sub_cmd */
        ivd_ctl_flush_ip_t *pv_api_ip_flv_1 = &pv_api_ip_flv_0;

        // initializing argument 'pv_api_op_PQl'
        ivd_ctl_flush_op_t pv_api_op_PQl_0;

        *(uint32_t*)((uint64_t)&pv_api_op_PQl_0 + 0) = v_Ymt[E.eat1() % 2]; /* u4_size */
        ivd_ctl_flush_op_t *pv_api_op_PQl_1 = &pv_api_op_PQl_0;

        dep_133 = ih264d_api_function(dep_173, pv_api_ip_flv_1, pv_api_op_PQl_1); /* vertex #20 */

    //}


    /* * * function pool #26 * * */
    //{
        // initializing argument 'pv_api_ip_AHt'
        ivd_video_decode_ip_t pv_api_ip_AHt_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_AHt_0 + 0) = v_TyA[E.eat1() % 2]; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_AHt_0 + 4) = 8; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_AHt_0 + 8) = 0; /* u4_ts */
        *(uint32_t*)((uint64_t)&pv_api_ip_AHt_0 + 12) = 0 /* DEAD */; /* u4_num_Bytes */

        uint8_t v_vLo_0 = 0 /* DEAD */;
        *(uint8_t**)((uint64_t)&pv_api_ip_AHt_0 + 16) = &v_vLo_0; /* pv_stream_buffer */
        *(uint32_t*)((uint64_t)&pv_api_ip_AHt_0 + 24) = 0 /* DEAD */; /* u4_num_bufs */

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            v_stI_0[i_0] = 0 /* DEAD */;
            v_stI_1[i_0] = &v_stI_0[i_0];
        }

        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint8_t**)((uint64_t)&pv_api_ip_AHt_0 + 32 + i_0*sizeof(uint8_t)) = v_stI_1[i_0]; /* pu1_bufs */
        }


        for (uint64_t i_0=0; i_0<64; ++i_0) {
            *(uint32_t*)((uint64_t)&pv_api_ip_AHt_0 + 544 + i_0*sizeof(uint32_t)) = buflen; /* u4_min_out_buf_size */
        }


        ivd_video_decode_ip_t *pv_api_ip_AHt_1 = &pv_api_ip_AHt_0;

        // initializing argument 'pv_api_op_SAI'
        ivd_video_decode_op_t pv_api_op_SAI_0;

        *(uint32_t*)((uint64_t)&pv_api_op_SAI_0 + 0) = 136; /* u4_size */

        ivd_video_decode_op_t *pv_api_op_SAI_1 = &pv_api_op_SAI_0;

        dep_133 = ih264d_api_function(dep_173, pv_api_ip_AHt_1, pv_api_op_SAI_1); /* vertex #21 */

    //}


    /* * * function pool #27 * * */
    //{
        // initializing argument 'pv_api_ip_FgN'
        ivd_rel_display_frame_ip_t pv_api_ip_FgN_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_FgN_0 + 0) = v_fEl[E.eat1() % 2]; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_FgN_0 + 4) = v_aOk[E.eat1() % 2]; /* e_cmd */
        *(uint32_t*)((uint64_t)&pv_api_ip_FgN_0 + 8) = 0 /* DEAD */; /* u4_disp_buf_id */
        ivd_rel_display_frame_ip_t *pv_api_ip_FgN_1 = &pv_api_ip_FgN_0;

        // initializing argument 'pv_api_op_PWd'
        ivd_rel_display_frame_op_t pv_api_op_PWd_0;

        *(uint32_t*)((uint64_t)&pv_api_op_PWd_0 + 0) = v_fbg[E.eat1() % 2]; /* u4_size */
        ivd_rel_display_frame_op_t *pv_api_op_PWd_1 = &pv_api_op_PWd_0;

        ih264d_api_function(dep_173, pv_api_ip_FgN_1, pv_api_op_PWd_1); /* vertex #22 */

    //}


    /* * * function pool #28 * * */
    //{
        // initializing argument 'pv_api_ip_Wdn'
        ivd_delete_ip_t pv_api_ip_Wdn_0;

        *(uint32_t*)((uint64_t)&pv_api_ip_Wdn_0 + 0) = 8; /* u4_size */
        *(uint32_t*)((uint64_t)&pv_api_ip_Wdn_0 + 4) = 6; /* e_cmd */
        ivd_delete_ip_t *pv_api_ip_Wdn_1 = &pv_api_ip_Wdn_0;

        // initializing argument 'pv_api_op_qGq'
        ivd_delete_op_t pv_api_op_qGq_0;

        *(uint32_t*)((uint64_t)&pv_api_op_qGq_0 + 0) = 8; /* u4_size */
        ivd_delete_op_t *pv_api_op_qGq_1 = &pv_api_op_qGq_0;

        dep_150 = ih264d_api_function(dep_173, pv_api_ip_Wdn_1, pv_api_op_qGq_1); /* vertex #14 */

    //}




    return 0;
}

// ------------------------------------------------------------------------------------------------
