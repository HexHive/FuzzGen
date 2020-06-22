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
 * Target Library: /external/libopus
 * Build Options: analysis=basic; arch=x64; permute=yes; failure=yes; 
 *                coalesce=yes; progressive=no; max-depth=4; seed=31337;
 *                min-buflen=32; max-buflen=4096;
 *
 * Issues: -
 *
 * ~~~ THIS FILE HAS BEEN GENERATED AUTOMATICALLY BY *FUZZGEN* AT: 25-02-2019 13:19:08 EET ~~~
 *
 */
// ------------------------------------------------------------------------------------------------
#include <cstdint>
#include <iostream>
#include <cstdlib>
#include <cassert>
#include <math.h>

/* headers for library includes */


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
uint8_t data_iWq[4096];
uint8_t *dep_13;
OpusDecoder* dep_18;
int32_t *dep_45;
OpusEncoder* dep_43;
uint32_t dep_14;
uint8_t data_FZP[4096];
int16_t pcm_qrU[8192];
OpusDecoder* dep_3;
OpusDecoder* dep_44;
int32_t *dep_12;
int16_t pcm_Ein[1920];
uint8_t data_fcK[3828];
uint8_t *dep_41;
uint32_t dep_42;
int64_t *dep_2;
int16_t pcm_AVt[8192];
int16_t *dep_4;
int32_t dep_11;
int16_t pcm_Oxg[11520];
uint8_t data_HIl[4096];


size_t buflen = 32; /* adaptable buffer length */
size_t nbufs = 3; /* total number of buffers */
size_t ninp  = 11; /* total number of other input bytes */


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
    if (size < 107 || size > 13323) return 0;

    /* all variables contain 3 random letters, so E cannot redefined */
    EatData E(data, size, ninp);

    buflen = (size - ninp) / nbufs - 1;             // find length of each buffer


    /* * * function pool #0 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'data_iWq'
        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            data_iWq[i_0] = E.buf_eat1();
        }

        // Dependence family #13 Definition
        dep_13 = (uint8_t *)data_iWq;

        // initializing argument 'error_hdc'
        int32_t error_hdc_0 = 0 /* WO */;
        int32_t *error_hdc_1 = &error_hdc_0;


        // initializing argument 'error_QMR'
        int32_t error_QMR_0 = 0 /* WO */;
        int32_t *error_QMR_1 = &error_QMR_0;

        // Dependence family #45 Definition
        dep_45 = (int32_t *)error_QMR_1;


        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_packet_get_bandwidth(dep_13); /* vertex #3 */
            }

            else if (perm[i] == 1) {
                dep_18 = opus_decoder_create(48000, 2, error_hdc_1); /* vertex #0 */
            }

            else if (perm[i] == 2) {
                dep_43 = opus_encoder_create(48000, 2, 2049, dep_45); /* vertex #0 */
            }

        }
    //}



    /* * * function pool #1 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(3, E.eatIntBw( NBYTES_FOR_FACTORIAL(3) ));
    
        // initializing argument 'data_FZP'
        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            data_FZP[i_0] = -1;
        }

        // initializing argument 'pcm_qrU'
        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            pcm_qrU[i_0] = 0;
        }



        for (int i=0; i<3; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_14 = opus_packet_get_nb_channels(dep_13); /* vertex #4 */
            }

            else if (perm[i] == 1) {
                opus_decode(dep_18, data_FZP, 16909318, pcm_qrU, 5760, 0); /* vertex #1 */
            }

            else if (perm[i] == 2) {
                opus_encoder_ctl(dep_43, 4002, 64000); /* vertex #1 */
            }

        }
    //}



    /* * * function pool #2 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    
        // initializing argument 'error_GbI'
        int32_t error_GbI_0 = 0 /* WO */;
        int32_t *error_GbI_1 = &error_GbI_0;



        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                dep_3 = opus_decoder_create(E.eat4(), dep_14, error_GbI_1); /* vertex #5 */
            }

            else if (perm[i] == 1) {
                dep_44 = opus_decoder_create(48000, 2, dep_45); /* vertex #2 */
            }

        }
    //}



    /* * * function pool #3 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    
        // initializing argument 'request_uft'
        int32_t request_uft_0 = 0 /* WO */;
        int32_t *request_uft_1 = &request_uft_0;

        // Dependence family #12 Definition
        dep_12 = (int32_t *)request_uft_1;

        // initializing argument 'pcm_Ein'
        for (uint64_t i_0=0; i_0<1920; ++i_0) {
            pcm_Ein[i_0] = 0 /* DEAD */;
        }

        // initializing argument 'data_fcK'
        for (uint64_t i_0=0; i_0<3828; ++i_0) {
            data_fcK[i_0] = 0 /* WO */;
        }

        // Dependence family #41 Definition
        dep_41 = (uint8_t *)&data_fcK;


        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_ctl(dep_3, 4039, dep_12); /* vertex #0 */
            }

            else if (perm[i] == 1) {
                dep_42 = opus_encode(dep_43, (const int16_t *)&pcm_Ein, 960, (uint8_t *)dep_41, 3828); /* vertex #3 */
            }

        }
    //}



    /* * * function pool #4 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    
        // initializing argument 'data_cCs'

        // initializing argument 'len_rMP'
        int64_t len_rMP_0 = buflen;
        int64_t *len_rMP_1 = &len_rMP_0;

        // Dependence family #2 Definition
        dep_2 = (int64_t *)len_rMP_1;
        // initializing argument 'pcm_AVt'
        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            pcm_AVt[i_0] = E.buf_eat2();
        }

        // Dependence family #4 Definition
        dep_4 = (int16_t *)pcm_AVt;
        // initializing argument 'decode_fec_XwX'
        int32_t decode_fec_XwX_0 = 0;

        // Dependence family #11 Definition
        dep_11 = (int32_t )decode_fec_XwX_0;

        // initializing argument 'pcm_Oxg'
        for (uint64_t i_0=0; i_0<11520; ++i_0) {
            pcm_Oxg[i_0] = 0 /* WO */;
        }



        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decode(dep_3, NULL, *dep_2, dep_4, *dep_12, dep_11); /* vertex #6 */
            }

            else if (perm[i] == 1) {
                opus_decode(dep_44, (uint8_t *)dep_41, dep_42, (int16_t *)&pcm_Oxg, 5760, 0); /* vertex #4 */
            }

        }
    //}



    /* * * function pool #5 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    
        // initializing argument 'data_HIl'
        for (uint64_t i_0=0; i_0<buflen; ++i_0) {
            data_HIl[i_0] = 0;
        }



        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decode(dep_3, data_HIl, *dep_2, dep_4, 5760, dep_11); /* vertex #1 */
            }

            else if (perm[i] == 1) {
                opus_encoder_destroy(dep_43); /* vertex #5 */
            }

        }
    //}



    /* * * function pool #6 * * */
    //{
        /* don't mess with bits. Keep it simple ;) */
        perm = kperm(2, E.eatIntBw( NBYTES_FOR_FACTORIAL(2) ));
    
        auto s_vDx[] = {dep_18, dep_3};


        for (int i=0; i<2; ++i) {
            if (0) { } /* this dummy statement is used to avoid corner cases */
    
            else if (perm[i] == 0) {
                opus_decoder_destroy(s_vDx[E.eat1() % 2]); /* vertex #2 */
            }

            else if (perm[i] == 1) {
                opus_decoder_destroy(dep_44); /* vertex #6 */
            }

        }
    //}





    return 0;
}

// ------------------------------------------------------------------------------------------------
