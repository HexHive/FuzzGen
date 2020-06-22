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
 * Target Library: .
 * Build Options: analysis=deep; arch=x64; permute=yes; failure=yes; 
 *                coalesce=yes; progressive=no; max-depth=4; seed=random;
 *                min-buflen=32; max-buflen=4096;
 *
 * Issues: 
 *   > Struct 'struct.anon.981' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.vpx_codec_priv_cb_pair' is not in the metadata file. Please update file accordingly.
 *   > Struct 'union.anon.0' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.anon.1' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.vpx_fixed_buf' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.vpx_codec_cx_pkt' is not in the metadata file. Please update file accordingly.
 *   > Struct 'union.anon' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.anon.0' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.vpx_codec_enc_cfg' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.vpx_rational64' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.VP8_CONFIG' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.block' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.yv12_buffer_config' is not in the metadata file. Please update file accordingly.
 *   > Struct 'union.int_mv' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.modeinfo' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.MB_MODE_INFO' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.ENTROPY_CONTEXT_PLANES' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.__jmp_buf_tag' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.__sigset_t' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.PARTITION_INFO' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.anon' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.search_site' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.mv_context' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.VP8Common' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.loop_filter_info_n' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.frame_contexts' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.BOOL_CODER' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.TOKENEXTRA' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.CODING_CONTEXT' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.MB_ROW_COMP' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.ENCODETHREAD_DATA' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.LPFTHREAD_DATA' is not in the metadata file. Please update file accordingly.
 *   > Struct 'union.sem_t' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.TOKENLIST' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.variance_vtable' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.FIRSTPASS_STATS' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.vp8_denoiser' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.denoise_params' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.LAYER_CONTEXT' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.vpx_codec_dec_cfg' is not in the metadata file. Please update file accordingly.
 *   > Struct 'union.anon.5' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.anon.6' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.vpx_codec_ctrl_fn_map' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.__va_list_tag' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.vpx_codec_stream_info' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.vpx_codec_frame_buffer' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.vpx_codec_enc_cfg_map' is not in the metadata file. Please update file accordingly.
 *   > Struct 'union.anon.980' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.vpx_codec_iface.2190' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.vpx_codec_ctx.2132' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.vpx_codec_alg_priv.2183' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.macroblockd.1179' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.nmv_context_counts' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.nmv_component_counts' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.frame_contexts.1161' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.nmv_context' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.nmv_component' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.VP9Common' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.RefCntBuffer' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.MV_REF' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.loop_filter_info_n.1160' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.loop_filter_thresh' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.LOOP_FILTER_MASK' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.VPxWorker' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.VPxWorkerImpl' is not in the metadata file. Please update file accordingly.
 *   > Struct 'union.pthread_mutex_t' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.__pthread_mutex_s' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.__pthread_internal_list' is not in the metadata file. Please update file accordingly.
 *   > Struct 'union.pthread_cond_t' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.__pthread_cond_s' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.__mm_loadl_epi64_struct' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.vpx_reader' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.LoopFilterWorkerData' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.VP9LfSyncData' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.JobQueueRowMt' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.ThreadData.1951' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.vpx_codec_ctrl_fn_map.2185' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.vpx_codec_dec_iface.2186' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.vpx_codec_enc_iface.2189' is not in the metadata file. Please update file accordingly.
 *   > Cannot find header file for struct 'vpx_codec_iface.2190'. Function is discarded.
 *
 *
 * ~~~ THIS FILE HAS BEEN GENERATED AUTOMATICALLY BY *FUZZGEN* AT: 06-08-2019 16:34:16 PDT ~~~
 *
 */
// ------------------------------------------------------------------------------------------------
#include <cstdint>
#include <iostream>
#include <cstdlib>
#include <cassert>
#include <math.h>

/* headers for library includes */
#include "vpx/vp8dx.h"
#include "vpx/vpx_decoder.h"
#include "vpx_ports/mem_ops.h"

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
const vpx_codec_iface* dep_6;
struct vpx_codec_ctx *dep_3;


size_t buflen = 32; /* adaptable buffer length */
size_t nbufs = 1; /* total number of buffers */
size_t ninp  = 10; /* total number of other input bytes */


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
    if (size < 133 ) return 0;

    /* all variables contain 3 random letters, so E cannot redefined */
    EatData E(data, size, ninp);

    buflen = (size - ninp) / nbufs - 1;             // find length of each buffer


    /* * * function pool #0 * * */
    //{
        dep_6 = vpx_codec_vp9_dx(); /* vertex #0 */

    //}


    /* * * function pool #1 * * */
    //{
        // initializing argument 'ctx_hEP'
        /*
        struct vpx_codec_ctx ctx_hEP_0;


        struct vpx_codec_iface v_aKn_0;


        struct vpx_codec_ctrl_fn_map v_GHD_0;

        *(struct vpx_codec_ctrl_fn_map**)((uint64_t)&v_aKn_0 + 48) = &v_GHD_0;


        struct vpx_codec_enc_cfg_map v_eNh_0;





        *(struct vpx_codec_enc_cfg_map**)((uint64_t)&v_aKn_0 + 104) = &v_eNh_0;

        *(struct vpx_codec_iface**)((uint64_t)&ctx_hEP_0 + 8) = &v_aKn_0;

        struct vpx_codec_dec_cfg v_aGm_0;

        *(struct vpx_codec_dec_cfg**)((uint64_t)&ctx_hEP_0 + 40) = &v_aGm_0;


        struct vpx_codec_priv v_rKA_0;

        */









        //*(struct vpx_codec_priv**)((uint64_t)&ctx_hEP_0 + 48) = &v_rKA_0;
        struct vpx_codec_ctx *ctx_hEP_1;// = &ctx_hEP_0;

        // Dependence family #3 Definition
        dep_3 = (struct vpx_codec_ctx *)ctx_hEP_1;
        // initializing argument 'cfg_Ywn'
        struct vpx_codec_dec_cfg cfg_Ywn_0;

        *(uint32_t*)((uint64_t)&cfg_Ywn_0 + 0) = (E.eat1() & 0x3f) + 1; /* UNKNOWN */
        *(uint32_t*)((uint64_t)&cfg_Ywn_0 + 4) = 0; /* UNKNOWN */
        *(uint32_t*)((uint64_t)&cfg_Ywn_0 + 8) = 0; /* UNKNOWN */
        struct vpx_codec_dec_cfg *cfg_Ywn_1 = &cfg_Ywn_0;

        if (vpx_codec_dec_init_ver(dep_3, dep_6, cfg_Ywn_1, 0, 12)) { /* vertex #4 */
            return 0;
        }

    //}


#define IVF_FRAME_HDR_SZ (4 + 8) /* 4 byte size + 8 byte timestamp */
#define IVF_FILE_HDR_SZ 32
    /* * * function pool #2 * * */
    //{
        // initializing argument 'data_XQD'
        char data_XQD_0 = 0;
        char *data_XQD_1 = &data_XQD_0;

        // initializing argument 'data_sz_RXm'
        uint64_t data_sz_RXm_0 = 0 /* DEAD */;
        uint64_t *data_sz_RXm_1 = &data_sz_RXm_0;

        // initializing argument 'user_priv_zVI'

         while (size > IVF_FRAME_HDR_SZ) {
            size_t frame_size = mem_get_le32(data);
            size -= IVF_FRAME_HDR_SZ;
            data += IVF_FRAME_HDR_SZ;
            frame_size = std::min(size, frame_size);

            vpx_codec_decode(dep_3, data, frame_size, NULL, 0); /* vertex #1 */


    //}


    /* * * function pool #3 * * */
    //{
        // initializing argument 'iter_xPd'

            vpx_codec_get_frame(dep_3, NULL); /* vertex #2 */
        }

    //}


    /* * * function pool #4 * * */
    //{
        vpx_codec_destroy(dep_3); /* vertex #3 */

    //}




    return 0;
}

// ------------------------------------------------------------------------------------------------
