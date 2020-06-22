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
 *   > Struct 'struct.AvxVideoInfo' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.anon' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct._IO_FILE' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.aom_image' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.aom_codec_iface.678' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.aom_codec_ctx.646' is not in the metadata file. Please update file accordingly.
 *   > Struct 'union.anon.0' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.aom_codec_dec_cfg' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.anon.2' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.aom_codec_priv_cb_pair' is not in the metadata file. Please update file accordingly.
 *   > Struct 'union.anon.0.1' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.anon.1' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.aom_fixed_buf' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.aom_codec_cx_pkt' is not in the metadata file. Please update file accordingly.
 *   > Struct 'union.anon.2' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.aom_codec_alg_priv.671' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.dist_wtd_comp_params' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.MV_REF' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.WarpedMotionParams' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.aom_film_grain_t' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.aom_codec_frame_buffer' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.yv12_buffer_config' is not in the metadata file. Please update file accordingly.
 *   > Struct 'union.anon' is not in the metadata file. Please update file accordingly.
 *   > Struct 'union.anon.8' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.anon.9' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct._hash_table' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.frame_contexts' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.nmv_context' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.nmv_component' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.AVxWorker' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.AVxWorkerImpl' is not in the metadata file. Please update file accordingly.
 *   > Struct 'union.pthread_mutex_t' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.__pthread_mutex_s' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.__pthread_internal_list' is not in the metadata file. Please update file accordingly.
 *   > Struct 'union.pthread_cond_t' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.__pthread_cond_s' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.__mm_storel_epi64_struct' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.aom_codec_ctrl_fn_map.673' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.__va_list_tag' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.aom_codec_dec_iface.674' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.aom_codec_enc_iface.677' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.aom_codec_enc_cfg_map' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.aom_codec_enc_cfg' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.aom_codec_ctx' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.aom_rational64' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.SkipModeInfo' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.QUANTS' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.macroblock_plane' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.INTERPOLATION_FILTER_STATS' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.SimpleRDState' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.MB_RD_RECORD' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.MB_RD_INFO' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct._CRC32C' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.TXB_RD_RECORD' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.TXB_RD_INFO' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.macroblockd' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.macroblockd_plane' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.INTERINTER_COMPOUND_DATA' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.PALETTE_MODE_INFO' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.FILTER_INTRA_MODE_INFO' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.InterpFilterParams' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.WienerInfo' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.SgrprojInfo' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.candidate_mv' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.__jmp_buf_tag' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.__sigset_t' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.cfl_ctx' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.MB_MODE_INFO_EXT' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.PALETTE_BUFFER' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.CompoundTypeRdBuffers' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.inter_modes_info' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.RdIdxPair' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct._crc_calculator' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.LV_MAP_COEFF_COST' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.LV_MAP_EOB_COST' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.COMP_RD_STATS' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.CB_COEFF_BUFFER' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.PICK_MODE_CONTEXT' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.Dequants' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.AV1Common' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.CurrentFrame' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.aom_dec_model_op_parameters' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.loop_filter_info_n' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.loop_filter_thresh' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.RestorationInfo' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.RestorationUnitInfo' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.RestorationStripeBoundaries' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.RestorationLineBuffers' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.CdefInfo' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.DeltaQInfo' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.CODING_CONTEXT' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.RATE_CONTROL' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.MBGRAPH_FRAME_STATS' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.MBGRAPH_MB_STATS' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.anon.12' is not in the metadata file. Please update file accordingly.
 *   > Struct 'union.anon.13' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.TX_TYPE_SEARCH' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.aom_variance_vtable' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.TWO_PASS' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.FIRSTPASS_STATS' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.GF_GROUP' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.RefBufferStack' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.InterModeRdModel' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.AV1RowMTSyncData' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.TOKENEXTRA' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.TOKENLIST' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.AV1LfSyncData' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.LoopFilterWorkerData' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.AV1LrSyncData' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.LoopRestorationWorkerData' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.aom_film_grain_table_t' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.AV1LevelInfo' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.AV1LevelStats' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.AV1LevelSpec' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.FrameWindowBuffer' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.FrameRecord' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.DECODER_MODEL' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.FRAME_BUFFER' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.DFG_INTERVAL_QUEUE' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.DFG_INTERVAL' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.LAYER_CONTEXT' is not in the metadata file. Please update file accordingly.
 *   > Struct 'union.anon.22' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.anon.23' is not in the metadata file. Please update file accordingly.
 *   > Struct 'struct.aom_codec_ctrl_fn_map' is not in the metadata file. Please update file accordingly.
 *   > Backward Slicing on vertex #2 failed. (decode_to_md5-main)
 *   > Backward Slicing on vertex #9 failed. (decode_to_md5-main)
 *   > AADG node #2 has no APICall object.
 *   > AADG node #9 has no APICall object.
 *   > Backward Slicing on vertex #2 failed. (decode_with_drops-main)
 *   > Backward Slicing on vertex #11 failed. (decode_with_drops-main)
 *   > AADG node #11 has no APICall object.
 *   > Backward Slicing on vertex #2 failed. (lossless_encoder-main)
 *   > Backward Slicing on vertex #4 failed. (lossless_encoder-main)
 *   > Backward Slicing on vertex #9 failed. (lossless_encoder-main)
 *   > AADG node #4 has no APICall object.
 *   > Backward Slicing on vertex #2 failed. (simple_decoder-main)
 *   > Backward Slicing on vertex #10 failed. (simple_decoder-main)
 *   > AADG node #10 has no APICall object.
 *   > Cannot find header file for struct 'aom_codec_iface.678'. Function is discarded.
 *   > Cannot find header file for struct '_IO_FILE'. Function is discarded.
 *
 *
 * ~~~ THIS FILE HAS BEEN GENERATED AUTOMATICALLY BY *FUZZGEN* AT: 12-08-2019 16:31:50 PDT ~~~
 *
 */
// ------------------------------------------------------------------------------------------------
#include <cstdint>
#include <iostream>
#include <cstdlib>
#include <cassert>
#include <math.h>

/* headers for library includes */

#include "aom/aom_encoder.h"
#include "aom/aomcx.h"
#include "common/tools_common.h"
#include "common/video_writer.h"
#include "aom/aom_decoder.h"
#include "aom/aomdx.h"
#include "common/video_reader.h"
#include "config/aom_config.h"
#include "aom_ports/mem_ops.h"


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
const int64_t v_IUo[] = {0, 49, 97, 118};


/* global variables */
uint8_t *perm;
const aom_codec_iface* dep_3;
struct AvxVideoReaderStruct* dep_24;
struct AvxVideoReaderStruct* dep_51;
char name_dCK[4];
struct AvxVideoReaderStruct* dep_91;
aom_codec_ctx_t dep_4;
struct aom_codec_ctx *dep_23;
struct aom_image *dep_69;
char data_jZE[262144];
struct aom_image* dep_58;
struct AvxVideoWriterStruct* dep_72;
//MD5Context *dep_36;
size_t *dep_29;
const uint8_t* dep_30;
size_t *dep_59;
const uint8_t* dep_61;
size_t *dep_96;
const uint8_t * dep_97;
aom_codec_ctx dep_75;
struct aom_codec_ctx *dep_66;
struct aom_image* dep_95;
struct aom_codec_ctx *dep_49;
struct aom_codec_ctx *dep_90;

size_t buflen = 32; /* adaptable buffer length */
size_t nbufs = 4; /* total number of buffers */
size_t ninp  = 18; /* total number of other input bytes */


/* function declarations (used by function pointers), if any */


// ------------------------------------------------------------------------------------------------
//
// Find the k-th permutation (in lexicographic order) in a sequence of n numbers,
// without calculating the k-1 permutations first. This is done in O(n^2) time.//
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
    if (size < 256 || size > 262144) return 0;



    /* all variables contain 3 random letters, so E cannot redefined */
    EatData E(data, size, ninp);

    buflen = (size - ninp) / nbufs - 1;             // find length of each buffer


    /* * * function pool #0 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(5, E.eatIntBw( NBYTES_FOR_FACTORIAL(5) ));
    
        // initializing argument 'filename_jdp'
        char filename_jdp_0 = 0;
        char *filename_jdp_1 = &filename_jdp_0;


        // initializing argument 'filename_BUt'
        char filename_BUt_0 = 0;
        char *filename_BUt_1 = &filename_BUt_0;


        // initializing argument 'name_dCK'
        for (uint64_t i_0=0; i_0<4; ++i_0) {
            name_dCK[i_0] = v_IUo[E.eat1() % 4];
        }


        // initializing argument 'filename_aXp'
        char filename_aXp_0 = 0;
        char *filename_aXp_1 = &filename_aXp_0;



        for (int i=0; i<5; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_3 = aom_codec_av1_dx(); /* vertex #0 */
            }

            else if (perm[i] == 1) {
//                dep_24 = aom_video_reader_open(filename_jdp_1); /* vertex #0 */
            }

            else if (perm[i] == 2) {
//                dep_51 = aom_video_reader_open(filename_BUt_1); /* vertex #0 */
            }

            else if (perm[i] == 3) {
//                get_aom_encoder_by_name((const char *)&name_dCK); /* vertex #0 */
            }

            else if (perm[i] == 4) {
//                dep_91 = aom_video_reader_open(filename_aXp_1); /* vertex #0 */
            }

        }
    //}


    /* * * function pool #1 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(5, E.eatIntBw( NBYTES_FOR_FACTORIAL(5) ));
        /*
        // initializing argument 'ctx_TnS'
        struct aom_codec_ctx ctx_TnS_0;


        struct aom_codec_iface v_YUD_0;


        struct aom_codec_ctrl_fn_map v_gVq_0;

        *(struct aom_codec_ctrl_fn_map**)((uint64_t)&v_YUD_0 + 48) = &v_gVq_0;


        struct aom_codec_enc_cfg_map v_mIr_0;






        *(struct aom_codec_enc_cfg_map**)((uint64_t)&v_YUD_0 + 104) = &v_mIr_0;

        *(struct aom_codec_iface**)((uint64_t)&ctx_TnS_0 + 8) = &v_YUD_0;

        struct aom_codec_dec_cfg v_nTz_0;


        *(struct aom_codec_dec_cfg**)((uint64_t)&ctx_TnS_0 + 40) = &v_nTz_0;


        struct aom_codec_priv v_tdL_0;











        *(struct aom_codec_priv**)((uint64_t)&ctx_TnS_0 + 48) = &v_tdL_0;
        struct aom_codec_ctx *ctx_TnS_1 = &ctx_TnS_0;

        // Dependence family #4 Definition
        dep_4 = (struct aom_codec_ctx *)ctx_TnS_1;
        */
        // initializing argument 'cfg_Opm'
        struct aom_codec_dec_cfg cfg_Opm_0;

        *(uint32_t*)((uint64_t)&cfg_Opm_0 + 0) = (E.eat1() % 0x3f) + 1; /* UNKNOWN */
        *(uint32_t*)((uint64_t)&cfg_Opm_0 + 4) = 0; /* UNKNOWN */
        *(uint32_t*)((uint64_t)&cfg_Opm_0 + 8) = 0; /* UNKNOWN */
        *(uint32_t*)((uint64_t)&cfg_Opm_0 + 12) = 1; /* UNKNOWN */
        *(uint32_t*)((uint64_t)&cfg_Opm_0 + 16) = 1; /* buffer_removal_time */

        struct aom_codec_dec_cfg *cfg_Opm_1 = &cfg_Opm_0;


        // initializing argument 'img_OeE'
        struct aom_image img_OeE_0;

        struct aom_image *img_OeE_1 = &img_OeE_0;

        // Dependence family #69 Definition
        dep_69 = (struct aom_image *)img_OeE_1;

        
        for (int i=0; i<5; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */

            else if (perm[i] == 0) {                
                if(aom_codec_dec_init_ver(&dep_4, dep_3, cfg_Opm_1, 0, 11)) { /* vertex #4 */
                    return 0;
                }
            }

            else if (perm[i] == 1) {
//                aom_video_reader_get_info(dep_24); /* vertex #1 */
            }

            else if (perm[i] == 2) {
//                aom_video_reader_get_info(dep_51); /* vertex #1 */
            }

            else if (perm[i] == 3) {
                aom_img_alloc(dep_69, (aom_img_fmt) 258, 0 /* DEAD */, 0 /* DEAD */, 1); /* vertex #1 */
            }

            else if (perm[i] == 4) {
//                aom_video_reader_get_info(dep_91); /* vertex #1 */
            }

        }
    //}

       

    /* * * function pool #2 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(4, E.eatIntBw( NBYTES_FOR_FACTORIAL(4) ));
    
        //aom_codec_ctx_t s_iBo[] = {&dep_4, &dep_4};
        // initializing argument 'data_jZE'
        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            data_jZE[i_0] = E.buf_eat1();
        }

        const uint8_t* s_OtN[] = {dep_61, (const uint8_t*)data_jZE};
      //  size_t s_hcf[] = {*dep_59, 0};
        // initializing argument 'user_priv_FwR'



        for (int i=0; i<4; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                aom_codec_decode(&dep_4, (uint8_t*)data_jZE, buflen, NULL); /* vertex #5 */
            }

            else if (perm[i] == 1) {
//                get_aom_decoder_by_fourcc(0 /* DEAD */); /* vertex #8 */
            }

            else if (perm[i] == 2) {
//                get_aom_decoder_by_fourcc(0 /* DEAD */); /* vertex #10 */
            }

            else if (perm[i] == 3) {
//                get_aom_decoder_by_fourcc(0 /* DEAD */); /* vertex #9 */
            }
       }
    //}



    /* * * function pool #3 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        //aom_codec_ctx_t s_yBB[] = {&dep_4, &dep_4};
        // initializing argument 'iter_QKd'


        // initializing argument 'iter_xOs'


        // initializing argument 'filename_HVq'
        char filename_HVq_0 = 0;
        char *filename_HVq_1 = &filename_HVq_0;

        // initializing argument 'info_RkC'
        AvxVideoInfo info_RkC_0;

        *(uint32_t*)((uint64_t)&info_RkC_0 + 0) = 0 /* DEAD */; /* UNKNOWN */
        *(uint32_t*)((uint64_t)&info_RkC_0 + 4) = 0; /* UNKNOWN */
        *(uint32_t*)((uint64_t)&info_RkC_0 + 8) = 0; /* UNKNOWN */
        *(uint32_t*)((uint64_t)&info_RkC_0 + 12) = 1; /* UNKNOWN */
        *(uint32_t*)((uint64_t)&info_RkC_0 + 16) = 30; /* UNKNOWN */

        AvxVideoInfo *info_RkC_1 = &info_RkC_0;



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                aom_codec_get_frame(&dep_4, NULL); /* vertex #5 */
            }

            else if (perm[i] == 1) {
                dep_58 = aom_codec_get_frame(&dep_4, NULL); /* vertex #6 */
            }

            else if (perm[i] == 2) {
//                dep_72 = aom_video_writer_open(filename_HVq_1, 0, info_RkC_1); /* vertex #3 */
            }

        }
    //}


    /* * * function pool #4 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(6, E.eatIntBw( NBYTES_FOR_FACTORIAL(6) ));
    
        // initializing argument 'context_IJh'
//        MD5Context context_IJh_0;

//        MD5Context *context_IJh_1 = &context_IJh_0;

        // Dependence family #36 Definition
//        dep_36 = (MD5Context *)context_IJh_1;

        // initializing argument 'file_tae'



        for (int i=0; i<6; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
//                aom_video_reader_read_frame(dep_24); /* vertex #3 */
            }

            else if (perm[i] == 1) {
//                MD5Init(dep_36); /* vertex #11 */
            }

            else if (perm[i] == 2) {
//                aom_video_reader_read_frame(dep_51); /* vertex #3 */
            }

            else if (perm[i] == 3) {
//                aom_img_write(dep_58, NULL); /* vertex #7 */
            }

            else if (perm[i] == 4) {
                aom_codec_control_(&dep_4, 31, 1); /* vertex #5 */
            }

            else if (perm[i] == 5) {
//                aom_video_reader_read_frame(dep_91); /* vertex #3 */
            }

        }
    //}


    /* * * function pool #5 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(7, E.eatIntBw( NBYTES_FOR_FACTORIAL(7) ));
    
        //struct aom_codec_ctx * s_xyl[] = {&dep_4, &dep_4};

        // initializing argument 'size_ocT'
        int64_t size_ocT_0 = 0;
        int64_t *size_ocT_1 = &size_ocT_0;

        // Dependence family #29 Definition
        dep_29 = (size_t *)size_ocT_1;

        // initializing argument 'a_ThI'


        // initializing argument 'size_fdt'
        int64_t size_fdt_0 = 0;
        int64_t *size_fdt_1 = &size_fdt_0;

        // Dependence family #59 Definition
        dep_59 = (size_t *)size_fdt_1;

        // initializing argument 'file_uGE'


        // initializing argument 'size_JzP'
        int64_t size_JzP_0 = 0;
        int64_t *size_JzP_1 = &size_JzP_0;

        // Dependence family #96 Definition
        dep_96 = (size_t *)size_JzP_1;


        for (int i=0; i<7; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                //aom_codec_destroy(&dep_4); /* vertex #7 */
            }

            else if (perm[i] == 1) {
//                dep_30 = aom_video_reader_get_frame(dep_24, dep_29); /* vertex #4 */
            }

            else if (perm[i] == 2) {
//                aom_codec_destroy(dep_23); /* vertex #6 */
            }

            else if (perm[i] == 3) {
                //MD5Update(dep_36, (uint8_t *), E.eat4()); /* vertex #12 */
            }

            else if (perm[i] == 4) {
//                dep_61 = aom_video_reader_get_frame(dep_51, dep_59); /* vertex #4 */
            }

            else if (perm[i] == 5) {
//                aom_img_read(dep_69, NULL); /* vertex #6 */
            }

            else if (perm[i] == 6) {
//                dep_97 = aom_video_reader_get_frame(dep_91, dep_96); /* vertex #4 */
            }

        }
    //}

    /* * * function pool #6 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(7, E.eatIntBw( NBYTES_FOR_FACTORIAL(7) ));
    
        // initializing argument 'user_priv_FHc'

        /*
        // initializing argument 'digest_LpH'
        char digest_LpH_0 = 0;
        char *digest_LpH_1 = &digest_LpH_0;


        // initializing argument 'ctx_aSR'
        struct aom_codec_ctx ctx_aSR_0;


        struct aom_codec_iface v_FWb_0;


        struct aom_codec_ctrl_fn_map v_rFc_0;

        *(struct aom_codec_ctrl_fn_map**)((uint64_t)&v_FWb_0 + 48) = &v_rFc_0;


        struct aom_codec_enc_cfg_map v_MgR_0;






        *(struct aom_codec_enc_cfg_map**)((uint64_t)&v_FWb_0 + 104) = &v_MgR_0;

        *(struct aom_codec_iface**)((uint64_t)&ctx_aSR_0 + 8) = &v_FWb_0;

        struct aom_codec_dec_cfg v_yCi_0;


        *(struct aom_codec_dec_cfg**)((uint64_t)&ctx_aSR_0 + 40) = &v_yCi_0;

        struct aom_codec_priv v_EMZ_0;

        


        *(struct aom_codec_priv**)((uint64_t)&ctx_aSR_0 + 48) = &v_EMZ_0;
        struct aom_codec_ctx *ctx_aSR_1 = &ctx_aSR_0;

        // Dependence family #75 Definition
        dep_75 = (struct aom_codec_ctx *)ctx_aSR_1;
        */
        // initializing argument 'img_IPc'
        struct aom_image img_IPc_0;

        struct aom_image *img_IPc_1 = &img_IPc_0;

        // initializing argument 'pts_jqe'
        int32_t pts_jqe_0 = 0 ;
        int32_t *pts_jqe_1 = &pts_jqe_0;

        // initializing argument 'pts_YIH'
        int32_t pts_YIH_0 = 0 ;
        int32_t *pts_YIH_1 = &pts_YIH_0;
        /*

        // initializing argument 'ctx_nCW'
        struct aom_codec_ctx ctx_nCW_0;


        struct aom_codec_iface v_EVB_0;


        struct aom_codec_ctrl_fn_map v_mia_0;

        *(struct aom_codec_ctrl_fn_map**)((uint64_t)&v_EVB_0 + 48) = &v_mia_0;


        struct aom_codec_enc_cfg_map v_BMe_0;






        *(struct aom_codec_enc_cfg_map**)((uint64_t)&v_EVB_0 + 104) = &v_BMe_0;

        *(struct aom_codec_iface**)((uint64_t)&ctx_nCW_0 + 8) = &v_EVB_0;

        struct aom_codec_dec_cfg v_cUs_0;


        *(struct aom_codec_dec_cfg**)((uint64_t)&ctx_nCW_0 + 40) = &v_cUs_0;


        struct aom_codec_priv v_ZVZ_0;











        *(struct aom_codec_priv**)((uint64_t)&ctx_nCW_0 + 48) = &v_ZVZ_0;
        struct aom_codec_ctx *ctx_nCW_1 = &ctx_nCW_0;

        // Dependence family #75 Definition
        dep_75 = (struct aom_codec_ctx *)ctx_nCW_1;
        */
        // initializing argument 'img_AkO'
        struct aom_image img_AkO_0;

        struct aom_image *img_AkO_1 = &img_AkO_0;

        // initializing argument 'pts_lqt'
        int32_t pts_lqt_0 = 0 /* DEAD */;
        int32_t *pts_lqt_1 = &pts_lqt_0;

        // initializing argument 'pts_xHc'
        int32_t pts_xHc_0 = 0 /* DEAD */;
        int32_t *pts_xHc_1 = &pts_xHc_0;


        if (aom_codec_enc_init(&dep_75, aom_codec_av1_cx(), NULL, 0)) {
            return 0;

        }

        printf("as\n");
        // initializing argument 'user_priv_pjw'
        for (int i=0; i<7; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
//                aom_video_reader_close(dep_24); /* vertex #7 */
            }

            else if (perm[i] == 1) {

                // initializing argument 'data_jZE'
                for (uint64_t i_0=0; i_0<buflen; ++i_0) {
                    data_jZE[i_0] = E.buf_eat1();
                }

                aom_codec_decode(&dep_4, (uint8_t*)data_jZE, buflen, NULL); /* vertex #10 */
            }

            else if (perm[i] == 2) {
            //    MD5Final(digest_LpH_1, dep_36); /* vertex #13 */
            }

            else if (perm[i] == 3) {
                //aom_codec_encode(&dep_75, img_IPc_1, *pts_jqe_1, 1, *pts_YIH_1); /* vertex #10 */
            }

            else if (perm[i] == 4) {
                //aom_codec_encode(dep_75, img_AkO_1, *pts_lqt_1, 1, *pts_xHc_1); /* vertex #13 */
            }

            else if (perm[i] == 5) {
//                aom_video_reader_close(dep_91); /* vertex #8 */
            }

            else if (perm[i] == 6) {
                // initializing argument 'data_jZE'
                for (uint64_t i_0=0; i_0<buflen; ++i_0) {
                    data_jZE[i_0] = E.buf_eat1();
                }

                aom_codec_decode(&dep_4, (uint8_t*)data_jZE, buflen, NULL); /* vertex #11 */
            }

        }
    //}


    /* * * function pool #7 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'iter_adb'


        // initializing argument 'iter_yYr'


        // initializing argument 'iter_vtM'

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
//                aom_codec_get_cx_data(dep_75, NULL); /* vertex #11 */
            }

            else if (perm[i] == 1) {
//                aom_codec_get_cx_data(dep_75, NULL); /* vertex #14 */
            }

            else if (perm[i] == 2) {
                dep_95 = aom_codec_get_frame(&dep_4, NULL); /* vertex #5 */
            }

        }
    //}


        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
        /*
        // initializing argument 'writer_OFK'
        struct AvxVideoWriterStruct writer_OFK_0;




        struct _IO_FILE v_PPU_0;

        *(struct _IO_FILE**)((uint64_t)&writer_OFK_0 + 24) = &v_PPU_0;
        struct AvxVideoWriterStruct *writer_OFK_1 = &writer_OFK_0;

        // initializing argument 'a_dKa'

        // initializing argument 'a_PbG'


        // initializing argument 'writer_AWD'
        struct AvxVideoWriterStruct writer_AWD_0;




        struct _IO_FILE v_mzx_0;

        *(struct _IO_FILE**)((uint64_t)&writer_AWD_0 + 24) = &v_mzx_0;
        struct AvxVideoWriterStruct *writer_AWD_1 = &writer_AWD_0;

        // initializing argument 'a_oOx'

        // initializing argument 'a_UoW'


        // initializing argument 'file_tyJ'

        */

        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
//                aom_video_writer_write_frame(writer_OFK_1, 0 /* DEAD */, (uint8_t ), ); /* vertex #12 */
            }

            else if (perm[i] == 1) {
//                aom_video_writer_write_frame(writer_AWD_1, 0 /* DEAD */, (uint8_t ), ); /* vertex #15 */
            }

            else if (perm[i] == 2) {
//                aom_img_write(dep_95, NULL); /* vertex #6 */
            }

        }
    //}



    /* * * function pool #8 * * */
    //{

    /* * * function pool #9 * * */
    //{
        //aom_img_free(dep_69); /* vertex #7 */

    //}


    /* * * function pool #10 * * */
    //{
        //aom_codec_ctx_t s_Gbi[] = {&dep_4, &dep_4};
        aom_codec_destroy(&dep_4); /* vertex #16 */

    //}


    /* * * function pool #11 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    

        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
//                aom_video_reader_close(dep_51); /* vertex #9 */
            }

            else if (perm[i] == 1) {
//                aom_video_writer_close(dep_72); /* vertex #8 */
            }

        }
    //}



    return 0;
}

// ------------------------------------------------------------------------------------------------
