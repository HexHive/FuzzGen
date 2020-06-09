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
 *
 *
 *
 * compose.cpp
 *
 * TODO: Write a small description.
 *
 */
// ------------------------------------------------------------------------------------------------
#include "compose.h"

#include <unistd.h>
#include <errno.h>


using namespace std;
using namespace interwork;


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



// ------------------------------------------------------------------------------------------------
// Code templates contain proper C++ code mixed with some special variables. Variables are in the
// form: $[var]$. There's a simple pattern matching engine that replaces these variables with the
// appropriate values, before template gets written to the file.
//
const string banner = R"(/*
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
 * Version: $[ver]$
 *
 * Target Library: $[lib]$
 * Build Options: $[opt1]$
 *                $[opt2]$
 *                $[opt3]$
 *
 * Issues: $[issue]$
 *
 * ~~~ THIS FILE HAS BEEN GENERATED AUTOMATICALLY BY *FUZZGEN* AT: $[date]$ ~~~
 *
 */)";



// ------------------------------------------------------------------------------------------------
#ifndef USE_STRICT_C_PROTOYPE
const string headers = R"(#include <cstdint>
#include <iostream>
#include <cstdlib>
#include <cassert>
#include <math.h>

/* headers for library includes */
$[incl]$

using namespace std;
)";

#else 
const string headers = R"(#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <math.h>

/* headers for library includes */
extern "C" {
$[incl]$}
)";

#endif



// ------------------------------------------------------------------------------------------------
const string globals = R"(/* calculate the number of bytes needed to hold a factorial */
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
$[pred]$

/* global variables */
uint8_t *perm;
$[glo]$

/* function declarations (used by function pointers), if any */
$[funcs]$
)";



// ------------------------------------------------------------------------------------------------
const string kperm = R"(//
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
})";



// ------------------------------------------------------------------------------------------------
const string eatdata = R"(//
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
)"

#ifdef USE_STRICT_C_PROTOYPE
R"(
            printf("eatIntBw(): All input has been eaten. This is a FuzzGen bug!\n");
            printf("size = %zu, delimiter = %zu, bwctr = %u, k = %u", size, delimiter, bwctr, k);        
)"

#else
R"(
            cout << "eatIntBw(): All input has been eaten. This is a FuzzGen bug!\n";
            cout << "size = " << size << ", delimiter = " << delimiter
                 << ", bwctr = " << bwctr << ", k = " << (int)k << "\n";
)"

#endif
R"(
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
)"

#ifdef USE_STRICT_C_PROTOYPE
R"(
            printf("eatIntFw(): All input has been eaten. This is a FuzzGen bug!\n");
            printf("size = %zu, delimiter = %zu, fwctr = %u, k = %u", size, delimiter, fwctr, k);        
)"

#else
R"(
            cout << "eatIntFw(): All input has been eaten. This is a FuzzGen bug!\n";
            cout << "size = " << size << ", delimiter = " << delimiter
                 << ", fwctr = " << fwctr << ", k = " << (int)k << "\n";        
)"

#endif
R"(
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
)"

#ifdef USE_STRICT_C_PROTOYPE
R"(
            printf("eatBuf(): All input has been eaten. This is a FuzzGen bug!\n");
)"

#else
R"(
            cout << "eatBuf(): All input has been eaten. This is a FuzzGen bug!\n";
)"

#endif
R"(
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
};)";



// ------------------------------------------------------------------------------------------------
const string mainDecl = R"(//
// LibFuzzer's initialization routine.
//
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void) argc;
    (void) argv;
)"

#ifdef USE_STRICT_C_PROTOYPE
R"(
    printf("[*] This fuzzer has been created by *FuzzGen*\n");
)"

#else
R"(
    cout << "[*] This fuzzer has been created by *FuzzGen*\n";
)"

#endif
R"(
    return 0;
}


// ------------------------------------------------------------------------------------------------
//
// LibFuzzer's main processing routine.
//
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* min size needed for Eat() to work properly */
    if (size < $[min_total]$ || size > $[max_total]$) return 0;

    /* all variables contain 3 random letters, so E cannot redefined */
    EatData E(data, size, ninp);

    buflen = (size - ninp) / nbufs - 1;             // find length of each buffer


$[body]$
    return 0;
})";



// ------------------------------------------------------------------------------------------------
// We comment out the brackets to prevent UAF, as local variables may define dependencies that
// are used in subsequent pools.
//
const string singlePool = R"(/* * * function pool #$[id]$ * * */
//{
$[func]$
//}


)";



// ------------------------------------------------------------------------------------------------
const string multiPool = R"(/* * * function pool #$[id]$ * * */
//{
    /* don't mess with bits. Keep it simple ;) */
    perm = kperm($[n]$, E.eatIntBw( NBYTES_FOR_FACTORIAL($[n]$) ));
$[decl]$
    for (int i=0; i<$[n]$; ++i) {
        if (0) { } /* this dummy statement is used to avoid corner cases */
$[func]$
    }
//}


)";



// ------------------------------------------------------------------------------------------------
const string multiPoolCall = R"(
else if (perm[i] == $[i]$) {
$[call]$
}
)";



// ------------------------------------------------------------------------------------------------
const string makeFile = R"(#
# Copyright (C) 2018 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
# ~~~ THIS MAKEFILE HAS BEEN GENERATED AUTOMATICALLY BY *FUZZGEN* AT: $[date]$ ~~~
#
#
LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_CERTIFICATE      := platform
LOCAL_C_INCLUDES       += bionic/libc/include $[incl]$
LOCAL_SRC_FILES        := $[fuzzsrc]$
LOCAL_CFLAGS           += -Wno-multichar -g -Wno-error
LOCAL_MODULE_TAGS      := optional
LOCAL_CLANG            := true
LOCAL_MODULE           := $[libname]$_fuzzer_$[model]$
LOCAL_SHARED_LIBRARIES := libutils $[libshr]$
LOCAL_STATIC_LIBRARIES += liblog $[libstc]$

include $(BUILD_FUZZ_TEST)
################################################################################
)";



// ------------------------------------------------------------------------------------------------
const string gloMakefile = R"(#
# Copyright (C) 2018 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
# ~~~ THIS MAKEFILE HAS BEEN GENERATED AUTOMATICALLY BY *FUZZGEN* AT: $[date]$ ~~~
#
#
LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

# decoder
include $[makefiles]$
)";



// ------------------------------------------------------------------------------------------------
// Simply initialize class members.
//
Composer::Composer(string currDir, Context *ctx) : ctx(ctx), currDir(currDir), header(ctx->header),
        global(ctx->global), inclDep(ctx->inclDep), tDef(ctx->tDef), ctr(0), minEat(0), maxEat(0),
        lastEat(0), maxlastEat(0) {

    if (ctx->seed) {
        srand(ctx->seed);                           // initialize with a given seed
    } else {
        srand(time(NULL));                          // initialize with random seed
    }


    /* a pool can have up to 20 functions (21! needs >64 bits) */
    if (MAX_FUNCS_PER_POOL > 20) {
        throw FuzzGenException("Composer(): A pool can have up to 20 functions");
    }
}



// ------------------------------------------------------------------------------------------------
// Create a new function pool.
//
uint16_t Composer::mkpool() {
    list <APICall*> pl;                             // declare an empty


    pool.push_back(pl);                             // extend pool by 1 element

    return ctr++;                                   // ctr is consistent with pool.size()
}



// ------------------------------------------------------------------------------------------------
// Push a function to an existing pool.
//
bool Composer::push(uint16_t poolID, APICall *call) {
    /* check if index is valid first */
    if (poolID < 0 || poolID >= pool.size()) {
        return false;                               // failure x(
    }

    pool[poolID].push_back(call);                   // push function

    return true;
}



// ------------------------------------------------------------------------------------------------
// Get pool's size.
//
size_t Composer::size(uint16_t poolID) {
    return pool[poolID].size();
}



// ------------------------------------------------------------------------------------------------
// Base function for substitution. This is actually the identity function.
//
string Composer::substitute(string templ) {
    return templ;
}



// ------------------------------------------------------------------------------------------------
// Substitute an arbitrary number of variables from a template. This function uses variadic
// templates to recursively substitute one variable at a time.
//
template<typename T, typename ... couple>
string Composer::substitute(string templ, T var, couple... replacement) {
    string tmp(templ);                              // make a hard copy
    string a = var.first;
    string b = var.second;


    /* regex doesn't work properly in C++11, so we use an alternative */
    for(size_t idx=0; (idx = tmp.find(var.first, idx)) != string::npos;
            idx += max(a.length(), b.length())) {

        tmp.replace(idx, a.length(),  var.second);
    }

    /* recursively move on the next variable substitution */
    return substitute(tmp, replacement...);
}



// ------------------------------------------------------------------------------------------------
// Cast an interwork basic type to a C++ type.
//
string Composer::toCppTy(Argument *arg) {

    switch(arg->baseType) {
        case Ty_void:   return "void";
        /* NOTE: 'singed char' and 'char' are different! Use 'char' instead of 'int8_t' */
        case Ty_i8:     return arg->isSigned ? "char"  : "uint8_t";
        case Ty_i16:    return arg->isSigned ? "int16_t" : "uint16_t";
        case Ty_i32:    return arg->isSigned ? "int32_t" : "uint32_t";
        case Ty_i64:    return arg->isSigned ? "int64_t" : "uint64_t";
        case Ty_float:  return "float";
        case Ty_double: return "double";
        case Ty_struct: {
            /* before you declare a struct make sure that the right #include is present */
            string name = substitute(arg->structName, P("struct.", ""));

            /* find struct's header */
            if (global.find(name) != global.end()) {
                includes.insert(global[name]);
            } else {
                ctx->reportIssue("Cannot find header file for struct '" + name + "'." +
                            " Function is discarded.");

//                throw FuzzGenStructException("toCppTy(): Cannot find struct's declaration."
//                                             " Much sad. Discarding current function");
            }

            /* if struct declared as "typedef" omit the "struct" keyword */
            if (tDef.find(name) != tDef.end()) {
                return name;
            }

            return "struct " + name;
        }
        case Ty_funcptr: return ptrTy;

    }

    fatal() << "Type with ID:" << arg->baseType << " is not implemented.\n";

    return "__NOT_IMPLEMENTED__";
}



// ------------------------------------------------------------------------------------------------
// Create a string of n stars.
//
inline string Composer::star(unsigned n) {
    string star;

    for (unsigned i=0; i<n; ++i, star+="*")
        { }

    return star;
}



// ------------------------------------------------------------------------------------------------
// Subscript an argument with an index.
//
inline string Composer::makeName(Argument *arg, unsigned subIdx) {
    return arg->name + "_" + to_string(subIdx);
}



// ------------------------------------------------------------------------------------------------
// Subscript a name with an index.
//
inline string Composer::makeName(string name, unsigned subIdx) {
    return name + "_" + to_string(subIdx);
}



// ------------------------------------------------------------------------------------------------
// Cast a dependence ID into a pretty string
//
inline string Composer::prettyDep(unsigned depID, string prefix="dep_") {
    return prefix + to_string(depID >> 16) +        // use offsets only if it's != 0
           (depID & 0xffff ? "_" + to_string(depID & 0xffff) : "");
}



// ------------------------------------------------------------------------------------------------
// Adjust a dependency type. The type of a dependency should match with the type of the argument/
// element that is being used. However it is possible to have a mismatch between the type of the
// definition and the type of the usage. For example:
//
//      Dependence Defined: int *dep_1; foo(dep_1);  // foo(int *); 
//      Dependence Used:    bar(*dep_1);             // bar(int);
// 
// Here, dependency is defined as a pointer, but it is used as an integer. This function detects
// such cases and adjusts the dependence type accordingly.
//
bool Composer::adjustDependency(Argument *arg) {

    if (arg->depTy != Dep_use) {                    // base check
        return false;                               // no adjustment made
    }

    if (depArg.find(arg->depID) == depArg.end()) {  // this should never happen
         return false;
        throw FuzzGenException("adjustDependency(): Dependency used without defined");
    }

    info(v3) << "Adjusting dependence ...\n";

    Argument *argDef = depArg[arg->depID];


    /* mismatch #1: off by 1 pointer. Use dereference */
    if (argDef->nptr[0] == arg->nptr[0] + 1 && arg->prefix == Pref_none) {      
        info(v3) << "argDef:  " << argDef->dump() << "\n";
        info(v3) << "arg   :  " << argDef->dump() << "\n";

        arg->prefix = Pref_deref;
        
        return true;
    }

    /* mismatch #2: off by 1 pointer (reverse direction). Use ampersand */
    else if (argDef->nptr[0] == arg->nptr[0] - 1 && arg->prefix == Pref_none) {
        info(v3) << "argDef:  " << argDef->dump() << "\n";
        info(v3) << "arg   :  " << argDef->dump() << "\n";

        arg->prefix = Pref_amp;
        
        return true;
    }
   
    /* mismatch #3: off by 1 dereference (reverse direction). Drop prefix */
    else if (argDef->nptr[0] == arg->nptr[0] - 1 && arg->prefix == Pref_deref) {
        info(v3) << "argDef:  " << argDef->dump() << "\n";
        info(v3) << "arg   :  " << argDef->dump() << "\n";

        arg->prefix = Pref_none;
        
        return true;
    }


    /* TODO: Consider more cases as you go */


    return false;
}



// ------------------------------------------------------------------------------------------------
// Generate n array indices for iterations, starting from iterFrom. Example:
//      iterIndices(3, 3) = "[i_3][i_4][i_5]"
//
inline string Composer::iterIndices(unsigned iterFrom, unsigned len) {
    string indices;

    for (unsigned i=0; i<len; indices+="[i_" + to_string(iterFrom + i++) + "]")
        { }

    return indices;
}



// ------------------------------------------------------------------------------------------------
// Generate n array indices starting from iter. However, this time use a single iterator.
// Example:
//      iterIndices(0, [77,88,99]) = "[i_0/(1*88*99) % 77][i_0/(1*99) % 88][i_0/(1) % 99]"
//
inline string Composer::iterIndices(unsigned iter, vector<size_t> sizes) {
    string indices, div;


    /* optimize the special case for 1D arrays */
    if (sizes.size() == 1) {
        return "[i_" + to_string(iter) + "]";
    }

    for (unsigned i=0; i<sizes.size(); ++i) {

        /* generate divisors first */
        div = "/(1";
        for (unsigned j=i+1; j<sizes.size(); ++j) {
            div += "*" + to_string(sizes[j]);
        }

        /* then indices */
        indices += "[i_" + to_string(iter) + div + ") % " + to_string(sizes[i]) + "]";
    }

    return indices;
}



// ------------------------------------------------------------------------------------------------
// Generate n array indices for array declarations. Each index has a constant size.
//
inline string Composer::declIndices(unsigned val, unsigned len) {
    string indices;

    for (unsigned i=0; i<len; ++i, indices+="[" + to_string(val) + "]")
        { }

    return indices;
}



// ------------------------------------------------------------------------------------------------
// Generate n array indices for array declarations. Each index has a predefined size.
//
inline string Composer::declIndices(const vector<size_t> sizes) {
    string indices;

    for (unsigned i=0; i<sizes.size(); indices+="[" + to_string(sizes[i++]) + "]")
        { }

    return indices;
}



// ------------------------------------------------------------------------------------------------
// Generate n nested for loops starting from iterator iterFrom. Each loop goes up to upper.
//
string Composer::makeForLoops(unsigned iterFrom, unsigned n, string upper, string body) {
    string loops, iter;


    /* create n nested for statements with the right indentation */
    for (unsigned i=0; i<n; ++i) {
        iter = "i_" + to_string(iterFrom + i);

        loops += tab("for (uint64_t " + iter + "=0; " + iter + "<" + upper +
                     "; ++" + iter + ") {\n", i);
    }


    /* to keep minEat consistent in nested makeForLoops(), we keep updating lastEat */
    if (lastEat & 0x80000000) {                     // lastEat set for 1st time?
        lastEat &= 0x7fffffff;                      // clear MSBit
        minEat  -= lastEat;                         // cancel increment that makeVal() did
        maxEat  -= maxlastEat;
    }

    /* multiply eat value by loop count */
    try {
        lastEat    *= stoul(upper) * n;
        maxlastEat *= stoul(upper) * n;

    } catch (const invalid_argument& invArg) {
        lastEat    *= ctx->minbuflen * n;           // upper is a variable. Use min buflen instead
        maxlastEat *= ctx->maxbuflen * n;           // the different with lastEat: find upper bound
    }


    /* it's much simpler if we use 2 variables (minEat, maxEat) for upper and lower bounds */
    minEat += lastEat;                              // minEat is aware of the loop now
    maxEat += maxlastEat;                           // maxEat as well
 
 
    /* write loop's body at the n'th indentation */
    loops += tab(body, n);

    /* close open curly brackets */
    for (int i=n-1; i>=0; --i) {                    // use "int" because we need i to be <0
        loops += tab("}\n", i);
    }

    return loops;
}



// ------------------------------------------------------------------------------------------------
// Generate n nested for loops starting from iterator iterFrom. This time upper is a vector, so
// each loop has a different upper bound.
//
string Composer::makeForLoops(unsigned iterFrom, vector<size_t> upper, string body) {
    string loops, iter;
    size_t n = upper.size();                        // get vector size

    size_t totalIter = 1;

    /* create n nested for statements with the right indentation */
    for (unsigned i=0; i<n; totalIter*=upper[i++]) {
        iter = "i_" + to_string(iterFrom + i);

        loops += tab("for (uint64_t " + iter + "=0; " + iter + "<" + to_string(upper[i]) +
                     "; ++" + iter + ") {\n", i);
    }


    /* to keep minEat consistent in nested makeForLoops(), we keep updating lastEat */
    if (lastEat & 0x80000000) {                     // lastEat set for 1st time?
        lastEat &= 0x7fffffff;                      // clear MSBit
        minEat  -= lastEat;                         // cancel increment that makeVal() did
        maxEat  -= maxlastEat;
    }

    /* multiply eat value by loop count */
    lastEat    *= totalIter;
    minEat     += lastEat;                              // minEat is aware of the loop now

    maxlastEat *= totalIter;
    maxEat     += maxlastEat;                           // maxEat as well
  

    /* write loop's body at the n'th indentation */
    loops += tab(body, n);

    /* close open curly brackets */
    for (int i=n-1; i>=0; --i) {                    // use "int" because we need i to be <0
        loops += tab("}\n", i);
    }

    return loops;
}



// ------------------------------------------------------------------------------------------------
// Create an assignment statement, that creates a value for an argument and then assigns this
// value to name.
//
string Composer::makeAssign(string name, Argument *arg, unsigned deep=0) {
    if (arg->baseType == Ty_struct) {
        /* structs can't be assigned directly. Element must be assigned instead */
        remark(v2) << "makeAssign() creates a struct!\n";


        /* if struct is initialized from another dependency, make the assignment first */
        if (depInit) {
            return name + " = (" + toCppTy(arg) + star(arg->nptr[0]) + ")" + 
                   prettyDep(arg->depIDInit) + ";\n\n" + makeStruct(arg, deep, name);
        }

        /* the recursion here can be arbitrary deep here */
        return name + ";\n\n" + makeStruct(arg, deep, name);
    }


    return name + " = " + makeVal(arg) + ";\n";
}



// ------------------------------------------------------------------------------------------------
// Create an assignment statement, to initialize a field in a struct. Because we don't know the
// element name,  assignment is done in the assembly style. For example:
//      *(uint8_t*) ((uint64_t)&foo + 16) = 1;
//
string Composer::makeAssign(Element *elt, unsigned displacement, string ampersand,
        string value, string name) {
    
    string assign, pointer, type;


    // e.g. to assign a i8* struct field:  *(uint8_t**)((uint64_t)&foo + i) = ...
    //      to assign a i8** struct field: *(uint8_t***)((uint64_t)&foo + i) = ...
    type    = "(" + toCppTy(elt) + star(elt->nptrs()) + "*)";
    pointer = "((" + ptrTy + ")";

    /* initialization of pointer structs does not require the ampersand */
    if (depInit == false) pointer += '&';        
 
    /* if a name is set, use it */
    if (name == "") name = elt->name;

    /* simply use the (previously defined) dependency */
    if (elt->depTy == Dep_use) {
        name = prettyDep(elt->depID);
    }

    pointer += name;
    pointer += " + " + to_string(elt->off);

    if (displacement == NO_DISPLACEMENT) {
        pointer += ")";
    } else {
        /* add the proper displacement */
        pointer += " + " + makeName("i", displacement) + "*sizeof(" + toCppTy(elt) + "))";
    }


    /* build the assignment */
    assign = "*" + type + pointer + " = " + ampersand + value + ";";

    /* for struct elements append the field name (just to make fuzzer for readable) */
    if (elt->fieldName != "") {
        assign += " /* " + elt->fieldName + " */";
    }


    /* if a dependency needs to be defined */
    if (elt->depTy & Dep_def) {
        ostringstream tmpGlo;

        /* declare global dependency */
        tmpGlo << toCppTy(elt) << star(elt->nptr[0]) << " " << prettyDep(elt->depID);

        // There's a very rare case that a dependency is essentially an array:
        //      ps_out_buf->u4_min_out_buf_size[0] = s_ctl_op.u4_min_out_buf_size[0];
        //      ps_out_buf->u4_min_out_buf_size[1] = s_ctl_op.u4_min_out_buf_size[1];
        //      ps_out_buf->u4_min_out_buf_size[2] = s_ctl_op.u4_min_out_buf_size[2];
        //
        // In that case, the dependency is an array. Please note that we do not consider
        // all weird cases with pointers as we do in makeDecl().
        if (displacement != NO_DISPLACEMENT && !elt->nptr[0]) {
            tmpGlo << declIndices(elt->sz);         // declaration is an array

            // a single for() loop suffices 
            // TODO: The correct approach considers all cases as in makeDecl(),
            //       but other cases are very rare.
            

            /* dependencies do not consume input. Be careful here*/
            size_t lastEat_bkp    = lastEat,        // take a backup of old lastEat
                   maxlastEat_bpk = maxlastEat;     // and maxlastEat
            
            lastEat    = 0;                         // zero these out (it's a dependency)
            maxlastEat = 0;

            depDecl += "\n" + 
                makeForLoops(
                    0, 
                    1, 
                    STR(elt->nsz), 
                    prettyDep(elt->depID) + iterIndices(0, 1) + " = " +
                        "*(" + toCppTy(elt) + star(elt->nptr[0]) + "*)" + pointer + ";\t"
                        "// Dependence family #" + prettyDep(elt->depID, "") + " definition\n"
                );
            depDecl += "\n";

            lastEat    = lastEat_bkp;               // restore lastEat
            maxlastEat = maxlastEat_bpk;

        } else {
            /* define dependency *AFTER* the API call (as API call sets OUT parameters) */
            depDecl += "\n";
            depDecl += prettyDep(elt->depID) + " = ";
            depDecl += "*(" + toCppTy(elt) + star(elt->nptr[0]) + "*)" + pointer + ";\t";
            depDecl += "// Dependence family #" + prettyDep(elt->depID, "") + " definition\n";
        }


        tmpGlo << ";\n";                            // finalize global declaration

        /* if dependency is not already declared, declare it */
        if (gloDecls.find(elt->depID) == gloDecls.end()) {
            glo << tmpGlo.str();

            gloDecls.insert(elt->depID);
        }

        /* save element that defines the dependence */
        depArg[elt->depID] = elt;
    } 

    return assign;
}



// ------------------------------------------------------------------------------------------------
// Create a variable with a random name.
//
string Composer::makeVar() {
    const int8_t alpha[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static set<string> prev;
    string var("v_");                               // all vars start with 'v_'


    /* generate a random name */
    for (int i=0; i<3; ++i) var += alpha[rand() % 52];


    /* make sure that each variable is unique. Don't rely on randomness ;) */
    if (prev.find(var) != prev.end()) {
        remark(v2) << "Variable '" << var << "' already declared! Trying another one...\n";
        return makeVar();
    }

    prev.insert(var);

    return var;
}



// ------------------------------------------------------------------------------------------------
// Add randomness to a variable name, to ensure its uniqueness.
//
void Composer::makeUnique(string &name) {
    name += "_" + makeVar().substr(2);
}



// ------------------------------------------------------------------------------------------------
// Generate the value that will be assigned to an argument. It might be random, or not; it
// depends on the attributes.
//
string Composer::makeVal(Argument *arg) {
    string val("0");


    /* base checks */
    if (!arg->attr) {
        throw FuzzGenException("makeVal(): Null attribute");

    } else if (arg->attr->flags == ATTR_FAILURE) {
        throw FuzzGenException("makeVal(): Invalid attribute");
    }

    /* check for dependencies first */
    if (!arg->nptrs() && arg->depTy & Dep_init) {
        /* watch out for dependencies in arrays (rare scenario) */
        return prettyDep(arg->depIDInit) + (arg->nsz != 1 ? iterIndices(0, arg->sz) : "");
    }

    /* simple case: Just initialize from the dependency */
    else if (arg->nptr[0] && !arg->nptr[1] && arg->depTy & Dep_init) {        
        return prettyDep(arg->depIDInit);
    }


    /* NULL pointers and dead arguments are simply set to 0 */
    if (arg->attr->flags == ATTR_DEAD) {
        return "0 /* DEAD */";
    }

    /* if it's an array size with a 0 predefined, use array size */
    else if (arg->attr->flags & ATTR_ARRAYSIZE && arg->attr->isZeroAttr()) {        
        return "buflen";
    }

    else if (arg->attr->flags & ATTR_NULLPTR) {
        return "NULL";
    }

    /* write-only arguments are not fuzzed */
    else if (arg->attr->flags & ATTR_WRITEONLY) {
        return "0 /* WO */";
    }

    /* properly fuzz arguments that can take a random value */
    else if ((arg->attr->flags & 0xff) == ATTR_RANDOM) {
        switch (arg->baseType) {
          case Ty_void:   val = "";                      break;
          case Ty_i8:     val = "E.eat1()"; lastEat = 1; break;
          case Ty_i16:    val = "E.eat2()"; lastEat = 2; break;
          case Ty_i32:    val = "E.eat4()"; lastEat = 4; break;
          case Ty_i64:    val = "E.eat8()"; lastEat = 8; break;
          case Ty_float:  val = "E.eat4()"; lastEat = 4; break;
          case Ty_double: val = "E.eat8()"; lastEat = 8; break;
          case Ty_struct: throw FuzzGenException("makeVal(): Structures cannot be fuzzed directly");          
          default:
                fatal() << "Type ID " << arg->baseType << " for argument " << arg->name
                        << " is not yet implemented. Setting it to 0...\n";

                return "0";
        }


        /* if we have a buffer, don't use regular input from 'E' */ 
        if (arg->attr->flags & ATTR_ARRAY) {
            val = val.substr(2);                    // drop "E."
            val = "E.buf_" + val;                   // quick n' dirty try to switch "eat" functions
        }

        maxlastEat = lastEat;


        minEat  += lastEat;                         // update "eat" count
        maxEat  += maxlastEat;

        lastEat |= 0x80000000;                      // MSBit to indicate that is set for 1st time
    }

    /* register all predefined arguments and randomly select one */
    else if (arg->attr->flags & ATTR_PREDEFINED) {
        if (arg->attr->getSize() == 1) {
            return arg->attr->dump();

        } else if (arg->attr->getSize() > 0) {
            string var = makeVar(),
                   sz  = "eat1";

            pred << arg->attr->dump(var) + "\n";

            ++minEat;
            ++maxEat;

            /* ok, assuming >65536 possible values is unrealistic */
            if (arg->attr->getSize() > 255) {
                sz = "eat2";
                ++minEat;
                ++maxEat;
            }

            if (arg->attr->getSize() > 65535) {
                fatal() << "Too many predefined values! Using the first 65535.\n";
            }

            return var + "[E." + sz + "() % " + to_string(arg->attr->getSize()) + "]";
        }
    }

    /* invariant arguments usually depend on another argument */
    else if (arg->attr->flags & ATTR_INVARIANT) {
        // the dependent argument will probably overwrite this
        return val;
    }

    /* arguments that hold array sizes, don't take random values */
    else if (arg->attr->flags & ATTR_ARRAYSIZE) {
        // (if attr is array size and predefined, predefined dominates)
        return "buflen";
    }

    /* function pointer argument, points a function declaration */
    else if (arg->attr->flags & ATTR_FUNCPTR) {

        if (arg->funcptr == nullptr) {              // base check
            throw FuzzGenException("makeVal(): NULL function pointer object");
        }

        if (arg->funcptr->hasDecl) {
            makeFuncDecl(arg->funcptr);             // declare the function (global)
    
            // update the function pointer name, to be consistent with the declaration
            arg->attr->addRef(arg->funcptr->funame);
        }

        /* return function pointer name (and cast to address first) */
        return "(" + ptrTy + ")" + arg->attr->getRef();
    }


    return val;
}



// ------------------------------------------------------------------------------------------------
// Generate a new function declaration, to serve as a function pointer.
//
void Composer::makeFuncDecl(interwork::FunctionPtr *func) {
    string   decl, body;
    unsigned i=0;


    if (func == nullptr) {                          // base check
        throw FuzzGenException("makeFuncDecl(): NULL function pointer object");
    }

    info(v2) << "Declaring a new function:\n" << func->dump() << "\n";

    if (!func->hasDecl) {                           // make sure that this never happens
        throw FuzzGenException("makeFuncDecl(): Declaring a function with no declaration");
    }

    if (func->funame == "") {                       // if there's no name,
        func->funame = makeVar();                   // give one
        func->funame.erase(0, 2);                   // drop "_v"
        func->funame = "func_" + func->funame;
    }


    decl = toCppTy(func->retval) + star(func->retval->nptr[0]) + " "
         + func->funame + "(";

    /* iterate over parameters */
    for (auto ii=func->params.begin(); ii!=func->params.end(); ++ii) {
        decl += toCppTy(*ii) + star((*ii)->nptr[0]) + " p" + to_string(i++) + ", ";

        /* focus on cases with simple pointers */
        if ((*ii)->nsz != 1 || (*ii)->nptr[1] != 0) {
            // TODO: Consider the more complicated cases
            throw FuzzGenStructException("makeFuncDecl(): Complicated function declarations "
                                         "are not supported");
        }
    }


    /* do the function body */
    if (func->callee != "") {                       // if external module found the wrapper
        
        body = func->callee + "(";
        for (auto &ii : func->paramMap) {           // invoke calee wit the appropriate arguments
            body += "p" + to_string(ii) + ", ";
        }

        body.pop_back();                            // drop last comma
        body.pop_back();
        body += ");";

        if (func->retValUsed) {                     // prepend a return
            // void* type becomes i8* in IR. To make compiler happy, we add an explicit casting
            body = "return (" + toCppTy(func->retval) + star(func->retval->nptr[0]) + ") " + body;
        }

        /* get include file */
        includes.insert(header[func->callee]);      // add the callee's

    } else {                                        // fall back to internal analysis
        body = "return " + makeVal(func->retval) + ";";
    }


    decl.pop_back();                                // drop the last comma
    decl.pop_back();
    decl += ") {\n" + tab(body) + "\n}";            // append function body

    funcs << decl << "\n\n";
}



// ------------------------------------------------------------------------------------------------
// Create C++ code that initializes all fields of a struct. The biggest problem here, is that
// llvm omits element names from structs, so we can't initialize them like "foo.a = 1". However
// we initialize each element, by having a pointer of the appropriate type that points to the
// appropriate offset (with respect to the alignment) inside this struct. For example consider
// the following struct:
//
//      struct foo {
//          char a;
//          int  b;
//          int  *c;
//      };
//
// which generates the following IR: %struct.foo = type { i8, i32, i32* }. To initialize an
// instance of foo we can write code in the assembly style:
//
//  struct foo a0;
//  uint32_t *ptr = ...;
//
//  *(uint8_t*) ((uint64_t)&a0 + 0) = 1;
//  *(uint32_t*)((uint64_t)&a0 + 4) = 2;
//  *(uint64_t*)((uint64_t)&a0 + 8) = (uint64_t)ptr;
//
// Note that we use uint64_t (8 byte pointers) in x64 architectures and uint32_t in x86.
//
//
// Unfortunately, things can get arbitrarly complicated when we have structs that consist of
// composite objects:
//
//      struct foo {
//          int ***a;
//          int b[11][22];
//          int ***c[33][44][55];
//          struct bar **d[66][77];
//      };
//
// The generated IR here is: %struct.foo = type { i32***, [11 x [22 x i32]],
// [33 x [44 x [55 x i32***]]], [66 x [77 x %struct.bar**]] }
//
// To deal with that we consider each case individually:
//
//
// --[ !. Null Elements
//
//  That's a special case that needs special attention. Consider struct A that contains a
//  pointer (or has it nested) to struct B. Struct B also has pointer to struct C. However,
//  struct C has a pointer to struct A. These three structs form a "cycle" and any attempt
//  to properly initialize them will endup in a deadlock.
//
//  To overcome this issue, we mark the pointer in C -that points back to A-, as a
//  "null pointer", and we simply set it to NULL.
//
//
// --[ 0. Basic Elements
//
//  Basic elements are initialized directly as described above.
//
//
// --[ 1. Simple Pointers: i32***
//
//  Simple pointers are initialized as follows:
//
//      uint32_t v_0    = ...;
//      uint32_t *v_1   = &v_0;
//      uint32_t **v_2  = &v_1;
//      *(uint32_t*)((uint32_t)&foo + 24) = &v_2;
//
//
// --[ 2. Array Pointers
//
//  These are simple pointers that are marked as arrays by magic().
//
//      uint32_t v_random[100][100][100];   /* global declaration */
//
//      for (uint64_t i_0=0; i_0<100; ++i_0) {
//          for (uint64_t i_1=0; i_1<100; ++i_1) {
//              for (uint64_t i_2=0; i_2<100; ++i_2) {
//                  v_random[i_0][i_1][i_2] = ...''
//              }
//          }
//      }
//
//      *(uint32_t*)((uint32_t)&foo + 24) = (uint32_t***)v_random;
//
//
// --[ 3. Simple Arrays: [11 x [22 x i32]]
//
//  Multi-dimensional arrays are merged and they're interpreted as a single dimensional
//  array.
//
//      /* array: [11 x [22 x i32]] */
//      for (uint64_t i_0=0; i_0<242; ++i_0) {
//          *(uint32_t*)((uint32_t)&foo + 32 + i_0*sizeof(uint32_t)) = ...;
//      }
//
//
// --[ 4. Simple Arrays as pointers: [512 x i8]*
//
//  This is a combination of [2] and [3]:
//
//      uint8_t v_random[512];   /* global declaration */
//      
//      for (uint64_t i_0=0; i_0<512; ++i_0) {
//          v_random[i_0] = ...;
//      }
//
//      *(uint8_t**)((uint64_t)&a_yvL_0 + 16) = v_random;
//
//
// --[ 5. Arrays of Simple Pointers: [66 x [77 x [88 x i32**]]]
//
//  This case is a combination of cases [1] and [3]:
//
//      /* global declarations */
//      uint32_t v_aNX_0[77][88][99];
//      uint32_t *v_aNX_1[77][88][99];
//      uint32_t **v_aNX_2[77][88][99];
//
//      for (uint64_t i_0=0; i_0<77; ++i_0) {
//          for (uint64_t i_1=0; i_1<88; ++i_1) {
//              for (uint64_t i_2=0; i_2<99; ++i_2) {
//                  v_aNX_0[i_0][i_1][i_2] = ...;
//                  v_aNX_1[i_0][i_1][i_2] = &v_aNX_0[i_0][i_1][i_2];
//                  v_aNX_2[i_0][i_1][i_2] = &v_aNX_1[i_0][i_1][i_2];
//              }
//          }
//      }
//
//      for (uint64_t i_0=0; i_0<670824; ++i_0) {
//          *(uint32_t*)((uint32_t)&aa_0 + 24 + i_0*sizeof(uint32_t)) =
//                  &v_aNX_2[i_0/(1*88*99) % 77][i_0/(1*99) % 88][i_0/(1) % 99];
//      }
//
//
// --[ 6. Arrays of Array Pointers
//
//  This case is a combination of cases [2] and [3]:
//
//      uint32_t v_PTR[670824][100][100][100];   /* global declaration */
//
//      for (uint64_t i_0=0; i_0<670824; ++i_0) {
//          for (uint64_t i_1=0; i_1<100; ++i_1) {
//              for (uint64_t i_2=0; i_2<100; ++i_2) {
//                  for (uint64_t i_3=0; i_3<100; ++i_3) {
//                      v_GTM[i_0][i_1][i_2][i_3] = ...;
//                      *(uint32_t*)((uint32_t)&foo + 24 + i_0*sizeof(uint32_t)) = 
//                                                                        (uint32_t***)v_GTM[i_0];
//                  }
//              }
//          }
//      }
//
string Composer::makeStruct(Element *elt, unsigned deep, string name) {
    ostringstream decl;                             // declaration stream
    string        varnam = makeVar();               // random variable (may not needed)
    int           i;                                // simply iterator


    /* if a different name is provided, use it */
    if (name == "") name = elt->name;

    /* for each (sub)element of the struct */
    for (list<Element*>::iterator ii=elt->subElements.begin(); ii!=elt->subElements.end(); ++ii) {
        Element *e = *ii;


        /* Attributes should not be NULL */
        if (!e->attr) {
            throw FuzzGenStructException("makeStruct(): Null Attributes at makeStruct()");
        }


        info(v2) << "  Element info:  " << e->dump() << "\n";

        adjustDependency(e);                  // adjust dependency (if exists)


        // TODO: come back to that
        if (e->subElements.size() < 1 && !e->setByExt) {
            info(v2) << "  Element did not set by external module. Skipping it...\n";

            continue;
        }


        // legacy approach for calculating offsets:
        //
        //  /* if offset is not aligned, roundup to a multiple of the type size */
        //  if (off % e->size) {
        //      off = (off + e->size - 1) & ~(e->size - 1);
        //  }


        lastEat    = 0;                             // clear any leftovers
        maxlastEat = 0;


        // --------------------------------------------------------------------- //
        //                        * [!] NULL Elements  *                         //
        // --------------------------------------------------------------------- //
        if (e->attr->flags & ATTR_NULLPTR) {
            e->baseType = Ty_i8;                    // it's ok if you tamper the type now

            // /* this is pretty much like a memset */
            // decl << "/* memset() a NULLPTR element */\n"
            //      << makeForLoops(deep, 1, STR(e->size),
            //             makeAssign(e, deep, NO_AMPERSAND, "0", name));

            decl << makeAssign(e, NO_DISPLACEMENT, NO_AMPERSAND, "NULL", name)
                 << "\n";
        }


        // --------------------------------------------------------------------- //
        //                        * [0] Basic Elements *                         //
        // --------------------------------------------------------------------- //
        else if (!e->nptrs() && e->nsz == 1) {
            if (e->isBasic()) {
                /* directly give a value to basic elements */
                decl << makeAssign(e, NO_DISPLACEMENT, NO_AMPERSAND, makeVal(e), name);
            } else {
                /* recursively initialize the embedded structure (subelements) */
                decl << makeStruct(e, deep, name);  // don't do deep+1 (?)
            }

            decl << "\n";
        }


        // --------------------------------------------------------------------- //
        //                        * [1] Simple Pointers *                        //
        // --------------------------------------------------------------------- //
        else if (e->nptr[0] > 0 && e->nsz == 1 && !(e->attr->flags & ATTR_ARRAY) && !deep) {
            /* make the initial declaration */
            decl << "\n" << toCppTy(e) << " " << makeAssign(makeName(varnam, 0), e);


            /* declare all pointers, with each pointer pointing to the previous declaration */
            for (i=0; i<e->nptr[0]-1; ++i) {
                decl << toCppTy(e) << " " << star(i+1) << makeName(varnam, i+1) << " = &"
                     << makeName(varnam, i) << ";\n";
            }

            /* the last pointer initializes the element */
            decl << makeAssign(e, NO_DISPLACEMENT, "&", makeName(varnam, e->nptr[0]-1), name);
            decl << "\n";
        }


        // --------------------------------------------------------------------- //
        //                         * [2] Array Pointers *                        //
        // --------------------------------------------------------------------- //
        else if (e->nptr[0] > 0 && e->nsz == 1 && ((e->attr->flags & ATTR_ARRAY) || deep)) {

            /* simple pointers translated to array pointers when deep > 0 */


            /* create the global declaration first */
            glo << toCppTy(e) << " " << varnam
                << declIndices(ctx->maxbuflen*e->basicSz(), deep + e->nptr[0]) << ";\n";

            decl << "\n"
                 << makeForLoops(deep, e->nptr[0], "buflen",
                        makeAssign(varnam +
                            iterIndices(0, deep + e->nptr[0]), e, deep + e->nptr[0]))
                 << "\n"
                 << makeAssign(e, NO_DISPLACEMENT, "", "(" + toCppTy(e) + star(deep + e->nptr[0]) +
                               ")" + varnam + iterIndices(0, deep), name)
                 << "\n";
        }


        // --------------------------------------------------------------------- //
        //                         * [3] Simple Arrays *                         //
        // --------------------------------------------------------------------- //
        else if (!e->nptrs() && e->nsz > 1) {
            string body("\n");


            if (e->baseType == Ty_struct) {
                body = makeStruct(e, deep + 1, name);
            } else {
                body = makeAssign(e, deep, NO_AMPERSAND, makeVal(e), name);
            }


            /* merge multi arrays into a single one */
            decl << "\n" << makeForLoops(deep, 1, STR(e->nsz), body) << "\n";
        }


        // --------------------------------------------------------------------- //
        //                   * [4] Simple Arrays as pointers *                   //
        // --------------------------------------------------------------------- //
        else if (e->nptr[0] > 0 && e->nsz > 1) {
            if (e->nptr[0] > 1) {
                // TODO: We do this for simple pointers. Make it more general
                throw FuzzGenStructException("makeStruct(): Multiple pointers are not implemented");
            }

            /* create the global declaration for buffer */
            glo << toCppTy(e) << " " << varnam
                << declIndices(e->nsz, deep + e->nptr[0]) << ";\n";

            /* create the for loop to initialize the buffer */
            decl << "\n"
                 << makeForLoops(deep, e->nptr[0], STR(e->nsz),
                        makeAssign(varnam +
                            iterIndices(0, deep + e->nptr[0]), e, deep + e->nptr[0]))
                 << "\n";

            /* assign buffer to the struct element */
            decl << makeAssign(e, NO_DISPLACEMENT, NO_AMPERSAND, varnam, name);
            decl << "\n";
        }


        // --------------------------------------------------------------------- //
        //                   * [5] Arrays of Simple Pointers *                   //
        // --------------------------------------------------------------------- //
        else if (!e->nptr[0] && e->nsz > 1 && e->nptr[1] > 0 && !(e->attr->flags & ATTR_ARRAY)) {

            /* declare all pointers, with each pointer pointing to the previous declaration */
            for (i=0; i<=e->nptr[1]; ++i) {
                glo << toCppTy(e) << " " << star(i) << makeName(varnam, i)
                    << declIndices(e->sz) << ";\n";
            }

 
            string body = makeAssign(makeName(varnam, 0) + iterIndices(0, deep + e->nptr[1]), e);


            /* declare all pointers, with each pointer pointing to the previous declaration */
            for (i=0; i<e->nptr[1]; ++i) {
                body += makeName(varnam, i+1) + iterIndices(0, deep + e->nptr[1]) + " = &" +
                        makeName(varnam, i)   + iterIndices(0, deep + e->nptr[1]) + ";\n";
            }

            decl << "\n" << makeForLoops(deep, e->sz, body) << "\n";


            if (e->baseType == Ty_struct) {
                /* TODO: This doesn't work perfect. Please check again */
                body = makeStruct(e, deep + 1);
            }
            else {
                body = makeAssign(e, deep, "", makeName(varnam, e->nptr[1]) +
                            iterIndices(0, e->sz), name);

            }

            /* merge multi arrays into a single one */
            decl << makeForLoops(deep, 1, STR(e->nsz), body) << "\n";
        }


        // --------------------------------------------------------------------- //
        //                    * [6] Arrays of Array Pointers *                   //
        // --------------------------------------------------------------------- //
        else if (!e->nptr[0] && e->nsz > 1 && e->nptr[1] > 0 && (e->attr->flags & ATTR_ARRAY)) {
            string body;

            /* create the global declaration first */
            glo << toCppTy(e) << " " << varnam
                << declIndices(e->nsz, 1)
                << declIndices(ctx->maxbuflen*e->basicSz(), e->nptr[1]) << ";\n";


            if (e->baseType == Ty_struct) {
                /* TODO: This doesn't work perfect. Please check again. */
                body = makeStruct(e, deep + 1 + e->nptr[1]);
            } else {
                body = makeAssign(e, deep, "", "(" + toCppTy(e) + star(e->nptr[1]) + ")" + 
                                    varnam + iterIndices(0, deep + 1), name);
            }


            decl << "\n"
                 << makeForLoops(deep, 1, STR(e->nsz),
                        makeForLoops(deep+1, e->nptr[1], "buflen",
                            makeAssign(varnam + iterIndices(0, deep+e->nptr[1]+1), e)) +
                            body) << "\n";
        }


        // --------------------------------------------------------------------- //
        //                             * [7] Error *                             //
        // --------------------------------------------------------------------- //
        else {
            fatal() << "Element cannot fall in any category. Initialization failed.\n";
        }


        /* each element should use a different random variable */
        varnam = makeVar();
    }


    /* just in case that this happens, inform the user */
    if (!elt->subElements.size()) {
        warning() << "A struct without elements has been encountered. Something is wrong x(\n";
    }


    /* return all declarations */
    return decl.str();
}



// ------------------------------------------------------------------------------------------------
// Create C++ code that initializes a variable before it gets passed to the fuzzed function.
// This function is invoked only for non basic arguments, as basic arguments do not require any
// prior declarations. This function is kinda similar to the makeStruct(), with some extra
// cases.
//
// An important thing to note is the byval attribute. When byval is set, it cancels one pointer
// from nptr[0], so we decrement nptr[0] by one. Also, if variable is a pointer, recursively
// create all required variables to ensure that the original variable has been initialized
// properly. Below are all the cases:
//
//
// --[ 1. Simple Pointers: i32*** %a
//
//  To declare this pointer, we need to build a chain of pointers, with each pointer having one
//  less indirection, untill we reach a basic argument that we can fuzz.
//
//      uint32_t a_0    = ...;
//      uint32_t *a_1   = &a_0;
//      uint32_t **a_2  = &a_1;
//      uint32_t ***a_3 = &a_2;
//
//
// --[ 2. Array Pointers
//
//  This is the same with [1], except that preprocessor has marked this pointer as "array". In
//  this case, pointer should not point to a single object, but to many. This gets translated as
//  a k-th dimensional array. Because we don't the size of the array, we set to an arbitrary,
//  value (100 in our case).
//
//      uint32_t b[100][100][100];  /* global declaration */
//
//      for (uint64_t i_0=0; i_0<100; ++i_0) {
//          for (uint64_t i_1=0; i_1<100; ++i_1) {
//              for (uint64_t i_2=0; i_2<100; ++i_2) {
//                  b[i_0][i_1][i_2] = ...;
//              }
//          }
//      }
//
//
// --[ 3. Multi-dimensional Arrays (as pointers): [11 x [22 x i32]]*
//
//  In this case we have an argument of type [][11][22], but it's used as a pointer according to
//  magic(). This is probably not gonna happen, but this case is included for completeness.
//
//      uint32_t c[11][22];     /* global declaration */
//
//      for (uint64_t i_0=0; i_0<11; ++i_0) {
//          for (uint64_t i_1=0; i_0<22; ++i_1) {
//              c[i_0][i_1] = ...;
//          }
//      }
//
//      function(..., &c, ...);
//
//
// --[ 4. Multi-dimensional Arrays (as arrays): [11 x [22 x i32]]*
//
//  This case is like [3], but the pointer is used as an array. For example:
//
//      uint32_t c2[100][11][22];     /* global declaration */
//
//      for (uint64_t i_0=0; i_0<100; ++i_0) {
//          for (uint64_t i_1=0; i_1<11; ++i_1) {
//              for (uint64_t i_2=0; i_1<22; ++i_2) {
//                  c2[i_0][i_1][i_2] = ...;
//              }
//          }
//      }
//
//      function(..., c2, ...);
//
//
// --[ 5. Multi-dimensional Arrays of Pointers (as pointers): [55 x [66 x i32**]]*
//
//  This is a tricky case and it happens when we have arguments like this: int **e[][55][66]:
//
//      /* global declarations */
//      uint32_t e_0[55][66];
//      uint32_t *e_1[55][66];
//      uint32_t **e[55][66];
//
//      for (uint64_t i_1=0; i_1<55; ++i_1) {
//          for (uint64_t i_2=0; i_1<66; ++i_2) {
//              e_0[i_1][i_2] = ...;
//              e_1[i_1][i_2] = &e_0[i_1][i_2];
//              e[i_1][i_2] = &e_1[i_1][i_2];
//          }
//      }
//
//      function(..., &e, ...);
//
//
// --[ 6. Multi-dimensional Arrays of Pointers (as arrays): [55 x [66 x i32**]]*
//
//  This is similar to [5], but the internal pointers are used as arrays, according to magic().
//  This happens when the argument has a type: int ***f[][55][66]
//
//      /* global declarations */
//      uint32_t **e2[100][55][66];
//      uint32_t e4[100][55][66][100][100];
//
//      for (uint64_t i_0=0; i_0<100; ++i_0) {
//          for (uint64_t i_1=0; i_1<55; ++i_1) {
//              for (uint64_t i_2=0; i_1<66; ++i_2) {
//                  for (uint64_t i_3=0; i_3<100; ++i_3) {
//                      for (uint64_t i_4=0; i_4<100; ++i_4) {
//                          e_4[i_0][i_1][i_2][i_3][i_4] = ...;
//                      }
//                  }
//
//                  e2[i_0][i_1][i_2] = (uint32_t**)e_4[i_0][i_1][i_2];
//              }
//          }
//      }
//
//      function(..., e2, ...);
//
couple Composer::makeDecl(Argument *arg, unsigned deep) {
    ostringstream decl;                             // declaration stream
    string        varnam;                           // final variable name (OUT)
    int           i;                                // simply iterator


    /* Attributes should not be NULL */
    if (!arg->attr) {
        throw FuzzGenException("makeDecl(): Null Attributes");
    }

    /* Basic attributes do not need any declarations */
    if (arg->isBasic() && arg->depTy == interwork::Dep_none) {
        throw FuzzGenException("makeDecl(): Declaring a basic argument");
    }


    // --------------------------------------------------------------------- //
    //                        * [!] NULL Elements  *                         //
    // --------------------------------------------------------------------- //
    if (arg->attr->flags & ATTR_NULLPTR) {
        varnam = "NULL";                            // simply assign to NULL
    }


    // --------------------------------------------------------------------- //
    //                        * [!] Special Case 1 *                         //
    // --------------------------------------------------------------------- //
    else if (arg->isBasic() && arg->depTy != interwork::Dep_none) {
   
        /* when a struct pointer is initialized from a dependency */
        depInit = true;                             // switch to dependence initialization mode

        /* make the initial declaration (start from 1 pointer) */
        decl << toCppTy(arg) << " " << makeAssign(makeName(arg, 0), arg);
        
        /* variable name that will be returned */
        varnam = makeName(arg, 0);

        depInit = false;                            // switch back to normal mode
    }


    // --------------------------------------------------------------------- //
    //                        * [!] Special Case 2 *                         //
    // --------------------------------------------------------------------- //
    else if (arg->nptr[0] == 1 && !arg->nptr[1] && arg->depTy & Dep_init) {

        /* when a struct pointer is initialized from a dependency */
        depInit = true;                             // switch to dependence initialization mode

        /* make the initial declaration (start from 1 pointer) */
        decl << toCppTy(arg) << " *" << makeAssign(makeName(arg, 0), arg);
        
        /* variable name that will be returned */
        varnam = makeName(arg, 0);

        depInit = false;                            // switch back to normal mode
    }


    // --------------------------------------------------------------------- //
    //                         * [0] Pure Structs *                          //
    // --------------------------------------------------------------------- //
/*
    else if (arg->baseType == Ty_struct) {
        // TODO: Not sure if this is needed at all (pass a struct by value???)
    }
*/

    // --------------------------------------------------------------------- //
    //                        * [1] Simple Pointers *                        //
    // --------------------------------------------------------------------- //
    else if (arg->nptr[0] > 0 && arg->nsz == 1 && !arg->nptr[1] &&
            !(arg->attr->flags & ATTR_ARRAY)) {

        /* make the initial declaration */
        decl << toCppTy(arg) << " " << makeAssign(makeName(arg, 0), arg);

        /* declare all pointers, with each pointer pointing to the previous declaration */
        for (i=0; i<arg->nptr[0]; ++i) {
            decl << toCppTy(arg) << " " << star(i+1) << makeName(arg, i+1) << " = &"
                 << makeName(arg, i) << ";\n";
        }

        /* variable name that will be returned */
        varnam = makeName(arg, arg->nptr[0]);
    }


    // --------------------------------------------------------------------- //
    //                        * [2] Array Pointers *                         //
    // --------------------------------------------------------------------- //
    else if (arg->nptr[0] > 0 && arg->nsz == 1 && !arg->nptr[1] &&
            (arg->attr->flags & ATTR_ARRAY)) {

        glo << toCppTy(arg) << " " << arg->name
            << declIndices(ctx->maxbuflen*arg->basicSz(), arg->nptr[0]) << ";\n";

        /* create loops to initialize this array */
        decl << makeForLoops(0, arg->nptr[0], "buflen",
                    makeAssign(arg->name + iterIndices(0, arg->nptr[0]), arg, arg->nptr[0]));

        varnam = arg->name;
    }


    // --------------------------------------------------------------------- //
    //            * [3]  Multi-dimensional Arrays (as pointers) *            //
    // --------------------------------------------------------------------- //
    else if (arg->nptr[0] == 1 && arg->nsz > 1 && !arg->nptr[1] &&
            !(arg->attr->flags & ATTR_ARRAY)) {

        glo << toCppTy(arg) << " " << arg->name << declIndices(arg->sz) << ";\n";

        /* initialize all dimensions one by one */
        decl << makeForLoops(0, arg->sz,
                    makeAssign(arg->name + iterIndices(0, arg->sz.size()), arg));

        /*
         *  TODO: for byval arrays, just omit the "&"
         */
        varnam = "&" + arg->name;
    }


    // --------------------------------------------------------------------- //
    //             * [4]  Multi-dimensional Arrays (as arrays) *             //
    // --------------------------------------------------------------------- //
    else if (arg->nptr[0] == 1 && arg->nsz > 1 && !arg->nptr[1] &&
            (arg->attr->flags & ATTR_ARRAY)) {

        glo << toCppTy(arg) << " "  << arg->name << declIndices(ctx->maxbuflen*arg->basicSz(), 1)
            << declIndices(arg->sz) << ";\n";

        /* create loops for the 1st pointer and for each dimension of the array */
        decl << makeForLoops(0, 1, "buflen",
                    makeForLoops(1, arg->sz,
                        makeAssign(arg->name + iterIndices(0, arg->sz.size()+1), arg)));

        varnam = arg->name;
    }


    // --------------------------------------------------------------------- //
    //       * [5] Multi-dimensional Arrays of Pointers (as pointers) *      //
    // --------------------------------------------------------------------- //
    else if (arg->nptr[0] == 1 && arg->nsz > 1 && arg->nptr[1] > 0 &&
            !(arg->attr->flags & ATTR_ARRAY)) {

        // TODO: This is not well tested??? TODO: Come back this comment

        /* declare all pointers, with each pointer pointing to the previous declaration */
        for (i=0; i<=arg->nptr[1]; ++i) {
            glo << toCppTy(arg) << " " << star(i) << makeName(arg->name, i)
                << declIndices(arg->sz) << ";\n";
        }


        string body = makeAssign(makeName(arg->name, 0) +
                                 iterIndices(0, deep + arg->nptr[1]), arg);


        /* declare all pointers, with each pointer pointing to the previous declaration */
        for (i=0; i<arg->nptr[1]; ++i) {
            body += makeName(arg->name, i+1) + iterIndices(0, deep + arg->nptr[1]) + " = &" +
                    makeName(arg->name, i)   + iterIndices(0, deep + arg->nptr[1]) + ";\n";
        }

        decl << makeForLoops(0, arg->sz, body);

        varnam = "&" + makeName(arg->name, arg->nptr[1]);
    }


    // --------------------------------------------------------------------- //
    //        * [6] Multi-dimensional Arrays of Pointers (as arrays) *       //
    // --------------------------------------------------------------------- //
    else if (arg->nptr[0] == 1 && arg->nsz > 1 && arg->nptr[1] > 0 &&
            (arg->attr->flags & ATTR_ARRAY)) {
        string body("\n");


        /* declare global arrays first */
        glo << toCppTy(arg) << " " << makeName(arg->name, 0)
            << declIndices(ctx->maxbuflen*arg->basicSz(), arg->nptr[0]) << declIndices(arg->sz)
            << declIndices(ctx->maxbuflen*arg->basicSz(), arg->nptr[1]) << ";\n"

            << toCppTy(arg) << " " << star(arg->nptr[1]) << makeName(arg->name, 1)
            << declIndices(ctx->maxbuflen*arg->basicSz(), arg->nptr[0]) + declIndices(arg->sz) << ";\n";


        /* create 3 groups of for loop to initialize nptr[0]. sz, and nptr[1] */
        body = makeForLoops(arg->nptr[0]+arg->sz.size(), arg->nptr[1], "buflen",
                            makeAssign(makeName(arg->name, 0) +
                                iterIndices(0, arg->nptrs() + arg->sz.size()), arg));


        body += "\n" + makeName(arg->name, 1) + iterIndices(0, arg->nptr[0] + arg->sz.size());
        body += " = (" + toCppTy(arg) + star(arg->nptr[1]) + ")" + makeName(arg->name, 0);
        body += iterIndices(0, arg->nptr[0] + arg->sz.size()) + ";\n";


        decl << makeForLoops(0, arg->nptr[0], "buflen",
                    makeForLoops(arg->nptr[0], arg->sz, body)) << "\n";


        varnam = makeName(arg->name, 1);
    }


    // --------------------------------------------------------------------- //
    //                             * [7] Error *                             //
    // --------------------------------------------------------------------- //
    else {
        fatal() << "Argument cannot fall in any category. Initialization failed.\n";
    }


    return P(tab(decl.str(), deep), varnam);
}



// ------------------------------------------------------------------------------------------------
// Create C++ code that initializes an API call argument. If any arguments need to be declared
//  first, makeDecl() is also invoked first.
//
couple Composer::makeArgument(Argument *arg) {
    string strArg = "", decl = "";


    info(v2) << "----------------------------------------------------------------\n";
    info(v2) << "  Argument info: " << arg->dump() << "\n";

    if (arg->name == "") {
        arg->name = "a";                    // prefix empty argument names (start with 'a')
    }

    makeUnique(arg->name);                  // add randomness to the argument
    adjustDependency(arg);                  // adjust dependency (if exists)


    if (arg->isBasic() && arg->depTy == Dep_none) {
        /* basic arguments take a value directly */
        strArg += makeVal(arg);

    } else if (arg->depTy == Dep_use) {                
        /* add prefix to the argument (if needed) */
        if (arg->prefix != Pref_none) {
            strArg += arg->prefix;
        }

        /* simply use the (previously defined) dependency */
        strArg += prettyDep(arg->depID);

    } else {
        /* composite arguments require some declarations first */
        couple d = makeDecl(arg, 0);

        decl += "// initializing argument '" + arg->name + "'\n";
        decl += d.first + "\n";

        /* add prefix to the argument (if needed) */
        if (arg->prefix != Pref_none) {
            strArg += arg->prefix;
        }
            
        /* check the dependence family  */
        if (arg->depTy & Dep_def) {
            string depCppTy = toCppTy(arg) + " " + star(arg->nptrs()); 

            /* declare global dependency (if not defined before) */
            if (gloDecls.find(arg->depID) == gloDecls.end()) {
                glo << depCppTy << prettyDep(arg->depID) << ";\n";

                gloDecls.insert(arg->depID);
            }

            /* define dependency */
            decl += "// Dependence family #" + prettyDep(arg->depID, "") + " Definition\n";
            decl += prettyDep(arg->depID) + " = (" + depCppTy + ")" + d.second + ";\n";

            /* and use it */
            strArg += prettyDep(arg->depID);

            /* save element that defines the dependence */
            depArg[arg->depID] = arg;               // if defined multiple times, get the last one

        } else {
            strArg += d.second; //arg->name + "_" + to_string(arg->nptr[0]);
        }
    }

    string tyCast = "";

    // Cast constant arrays to avoid compile errors such as: 
    //      "no known conversion from 'uint16_t [8192]' to 'short *'"
    if (arg->nsz > 1) {

        tyCast = "(" + string(arg->isConst ? "const " : "") + 
                       toCppTy(arg) + " " + star(arg->nptrs()) + ")";
    }


    return P(decl, tyCast + strArg);
}



// ------------------------------------------------------------------------------------------------
// Create C++ code that performs an API call. If any arguments need to be declared first,
// makeDecl() is also invoked first.
//
couple Composer::makeCall(APICall *call, int poolID) {
    string func(call->name + "("),
           decl;


    emph(v1) << "================================ POOL #" << poolID << " "
             << "================================\n";
    info(v1) << "Generating code for " << call->name << "() ...\n"; 
    info(v1) << "Return Value (" << prettyDep(call->depID) << ") : " << call->retVal << "\n";


    for (size_t i=0; i<call->depAsg.size(); ++i)
        remark(v2) << "D: " << prettyDep(call->depAsg[i]) << "\n";

    depDecl = "";                                   // clear any previous dependency declarations


    try {
        /* configure each argument */
        for (auto ii=call->args.begin(); ii!=call->args.end(); ++ii) {
            Argument *arg = *ii;

            lastEat = maxlastEat = 0;
            
            couple a = makeArgument(arg);
            decl += a.first;


            if (arg->switchArgs.size() > 0) {
                string var = "s";                   // this is a switch variable
                makeUnique(var);

                /* create an array with all candidate arguments */
                string sw = "auto " + var + "[] = {" + a.second + ", ";

                /* TODO: Switches in elements? */
                for (size_t j=0; j<arg->switchArgs.size(); ++j) {
                    lastEat = maxlastEat = 0;

                    couple a = makeArgument(arg->switchArgs[j]);
                    decl += a.first;

                    sw += a.second + ", ";
                } 

                sw.pop_back();
                sw.pop_back();
                sw += "};\n";

                decl += sw;

                /* select 1 argument at runtime */
                func += var + "[E.eat1() % " + to_string(arg->switchArgs.size()+1) + "], ";

            } else {
                func += a.second + ", ";            // finish argument with a comma
            }
        }

    } catch(FuzzGenStructException &e) {
        /* exceptions from makeStruct() should not abort program */
        fatal() << "An exception was thrown: " << e.what() << ".\n";

        return P("", tab("/* can't find struct's #include. Discard. */"));
    }


    if (call->nargs > 0) {
        func.erase(func.length() - 2);              // drop last comma (if exists)
    }

    func += ")";


    /* make sure that return value is not NULL */
    if (!call->retVal) {
        throw FuzzGenException("makeCall(): NULL return value object");
    }                
            
    /* do we have a dependence definition from return value? */
    if (call->depTy != Dep_none) {
        bool tyMatch = false;                       // type match flag


        /* declare global dependency */
        if (gloDecls.find(call->depID) == gloDecls.end()) {

            /* check if return value is signed as you did with parameters */
            if (ctx->signParam.find(call-> name)            != ctx->signParam.end() &&
                ctx->signParam[call->name].find("$RETVAL$") != ctx->signParam[call->name].end()) {

                    info(v3) << "Return Value is signed.\n";  

                    call->retVal->isSigned = 1;
            } else {
                call->retVal->isSigned = 0;
            }
    

            glo << toCppTy(call->retVal) << star(call->retVal->nptrs()) << " "
                << prettyDep(call->depID) << ";\n";

            gloDecls.insert(call->depID);

            tyMatch = true;                         // the 1st time we always have type match
        } else {
            // Check if we have a type match. For instance, assume the following code:
            //      int err; 
            //      
            //      api_foo(&err);
            //      err = api_bar();
            //
            // FuzzGen first analyzes foo(), so it declares err as int*. However it cannot
            // cast the (integer) return value to int *. The best way to deal with this
            // is to just ignore the assignment of the return value.
            //
            if (depArg.find(call->depID) != depArg.end()) {
                if (depArg[call->depID]->tyStr == call->retVal->tyStr) {
                    tyMatch = true;
                }
            }
        }

        /* if we have a type match, declare dependency (to avoid compilation errors) */
        if (tyMatch == 1) {
            /* add an if statement around call to check its return value */
            func = prettyDep(call->depID) + " = " + func;

            /* save element that defines the dependency */
            depArg[call->depID] = call->retVal;


            for (size_t i=0; i<call->depAsg.size(); ++i)
                depArg[call->depAsg[i]] = call->retVal;
        }
    }


    /* check return value? */
    if (call->vals.size() > 0) {
        // Supoorting >1 return values, requires the type of the return value to declare
        // additional variables and compare failure values one by one.
        if (call->vals.size() > 1) {
            throw FuzzGenException("makeCall(): Multiple return values are not supported.");
        }

        if (call->depTy == Dep_def) {
            /* add an if statement around call to check its return value */
            func = "if ( (" + func + ") " + call->ops[0] + " " + to_string(call->vals[0]) + 
                        ") {\n" + "    return 0;    // failure\n" +
                   "}";
        }
    } else {
        func += ";";
    }


    /* if we have more dependencies (from node merging) define them as well */
    if (call->depAsg.size() > 0) {
        for (auto jj=call->depAsg.begin(); jj!=call->depAsg.end(); ++jj) {
            func += "\n" + prettyDep(*jj) + " = " + prettyDep(call->depID) + ";";
        }
    }

    /* add the AADG vertex that API call came from to ease debugging */
    func += " /* vertex #" + to_string(call->vertex) + " */";


    return P(tab(decl), tab(func + depDecl));
}



// ------------------------------------------------------------------------------------------------
// Visitor class that is being used as a callback upon DFS.
//
class DFSVisitor : public dfs_visitor<> {
public:
    /* class constructor */
    DFSVisitor(bool &cycle) : cycle(cycle) { }

    /* callback that is invoked when a backward edge is encountered */
    template <class Edge, class Graph>
    void back_edge(Edge, Graph &) {
        /* if graph has a back edge, then it contains a cycle */
        cycle = true;
    }


private:
    bool &cycle;                                    // true if graph has a cycle
};



// ------------------------------------------------------------------------------------------------
// At this point there's the appropriate #include header for each function that is being present
// in the fuzzer. However, placing these includes at any order, it's likely to result in a
// compile error, because these includes might have internal dependencies (an include might use
// types that are declared in another include). These dependencies can be exposed by looking at
// the #include statements of the library's .c file.
//
// We collect all these dependencies and we make a graph that each node represents an #include
// file and each edge a dependence between 2 includes. Having built this graph we can perform a
// topological sort and get a valid order of the #include statements.
//
// There's also a small caviet here. Assume foo.h has no #includes, but foo.c includes bar.h.
// Right now we include bar.h and we stop there (we're going only 1 step deep). This is fine
// most of the times, but consider the case where bar.c defines baz.h. The question here is
// whether foo.h should depend on baz.h. Although the answer in the general case is yes, here
// we don't consider it. We're interested in fuzzing functions from the API, and these functions
// should be accessible without needing any internal includes. This can implicitly help us
// to discard root functions that are not part of the API.
//
string Composer::fixIncludes(void) {
    /* directed graph type */
    typedef adjacency_list<vecS, vecS, directedS> DiGraph;

    /* edge iterator type */
    typedef graph_traits<DiGraph>::edge_iterator edge_iterator;

    map<int, string> toStr;                         // mapping from vertices to strings
    map<string, int> toVtx;                         // mapping from strings to vertices
    DiGraph          G(0);                          // "includes" graph
    string           incl;                          // final C++ #include statements


    info(v1) << "Fixing #include dependencies for " << includes.size() << " headers...\n";


    /* build the dependence graph from the include headers */
    for (auto ii=includes.begin(); ii!=includes.end(); ++ii) {
        vector<string> deps;                        // dependencies for each include
        string         cFile,                       // auxiliary
                       hdr = ii->substr(ii->find_last_of("/")+1);


        /* exception: standard C libraries */
        if (!ii->compare(0, 20, "bionic/libc/include/")) {            
            incl += "#include <" + ii->substr(20) + ">\n";
            continue;
        }

        /* if include header is not under current module, ignore it */
        if (ii->compare(0, ctx->libPath.size(), ctx->libPath)) {
            continue;
        }

        /* create a node in the dependence graph (if needed) */
        if (toVtx.find(hdr) == toVtx.end()) {
            int node = add_vertex(G);

            toVtx[hdr]  = node;
            toStr[node] = hdr;
        }


        /* check header dependencies for the include's .c file as well */
        cFile = ii->substr(0, ii->find_last_of(".")) + ".c";

        /* get header's dependencies (if any) */
        // (.h #includes will be added to the source by the compiler, so we ignore them)
        //
        // if (inclDep.find(*ii) != inclDep.end()) {
        //     deps = inclDep[*ii];
        // }

        if (inclDep.find(cFile) != inclDep.end()) {
            /* take these dependencies as well */
            deps.insert(deps.end(), inclDep[cFile].begin(), inclDep[cFile].end());
        }


        /* for each dependence */
        for (auto &jj : deps) {

            /* create a node in the dependence graph (if needed) */
            if (toVtx.find(jj) == toVtx.end()) {
                int node = add_vertex(G);

                toVtx[jj]   = node;
                toStr[node] = jj;
            }

            /* add an edge between hdr -> jj to indicate the dependence */
            add_edge(toVtx[hdr], toVtx[jj], G);


            // The new edge it's possible to create a cycle. In that case the order of the
            // these #includes doesn't matter, as it's being solved by forward declarations.
            bool       hasCycle = false;
            DFSVisitor V(hasCycle);

            depth_first_search(G, visitor(V));      // do a DFS looking for backward edges

            if (hasCycle) {
                warning() << "Edge ('" << hdr << "', '" << jj << "') creates a cycle."
                          << " Removing it...\n";

                /* clear cycle */
                remove_edge(toVtx[hdr], toVtx[jj], G);
            }
        }
    }


    info(v1) << "Dependence Graph successfully created. |V| = " << num_vertices(G)
             << " and |E| = " << num_edges(G) << "\n";

    /* print all edges (= all dependencies between headers)  */
    info(v2) << "Dumping all dependencies...\n";

    for(edge_iterator ii=edges(G).first; ii!=edges(G).second; ++ii) {
        info(v2) << "  " << toStr[source(*ii, G)] << " -> " << toStr[target(*ii, G)] << "\n";
    }


    /* do a topological sort to get a valid order of the include headers */
    deque<int> order;
    topological_sort(G, front_inserter(order));

    /* create the #include statements */
    for (auto ii=order.rbegin(); ii!=order.rend(); ++ii) {
        incl += "#include \"" + toStr[*ii] + "\"\n";
    }


    info(v1) << "Done.\n";

    /* return #include statements */
    return incl;
}



// ------------------------------------------------------------------------------------------------
// Create the (partial) fuzzer file. Function takes an (potentially) incomplete body of the final
// fuzzer, and creates the C++ file. If progressive generation is enabled, function also creates
// the makefile (Android.mk) and tries to compile the fuzzer. If compilation fails, we know that
// something is wrong with current fuzzer's body, so we can rollback and remove the problematic
// function.
//
// Upon success, function returns 1. If a compilation error occurs, function returns 0. Otherwise
// (all other errors) a -1 is returned.
//
int Composer::makeFuzzer(string outfile, int flags, string body) {
    ofstream ofs(currDir + "/" + outfile);
    string   opt1, opt2, opt3;                      // build options


    info(v1) << "Generating fuzzer file...\n";

    if (!ofs) {
        fatal() << "Cannot create file.\n";

        remark(v0) << "Error Message: '" << strerror(errno) << "'.\n";        
        return -1;                                  // failure
    }

    /* clear empty lines that contain only whitespaces */
    // body = substitute(body,
    //                   P("\n    \n",                 "\n\n"),
    //                   P("\n        \n",             "\n\n"),
    //                   P("\n            \n",         "\n\n"),
    //                   P("\n                \n",     "\n\n"),
    //                   P("\n                    \n", "\n\n"));


    /* make build options */
    switch(flags & FLAG_ANALYSIS){
      case dumb:  opt1 = "analysis=dumb; ";  break;
      case basic: opt1 = "analysis=basic; "; break;
      case deep:  opt1 = "analysis=deep; ";
    }

    opt1 += "arch="        + string(flags & FLAG_ARCH64      ? "x64" : "x86") + "; " +
            // "external="    + string(flags & FLAG_EXTERNAL    ? "yes" : "no")  + "; " +
            "permute="     + string(flags & FLAG_PERMUTE     ? "yes" : "no")  + "; " +
            "failure="     + string(flags & FLAG_FAILURE     ? "yes" : "no")  + "; ";
    opt2 =  "coalesce="    + string(flags & FLAG_COALESCE    ? "yes" : "no")  + "; " +
            "progressive=" + string(flags & FLAG_PROGRESSIVE ? "yes" : "no")  + "; " +
            "max-depth="   + to_string(ctx->maxDepth) + "; "
            "seed="        + (!ctx->seed ? "random" : to_string(ctx->seed)) + ";";
    opt3 =  "min-buflen="  + to_string(ctx->minbuflen) + "; " +
            "max-buflen="  + to_string(ctx->maxbuflen) + ";";           


    string delim = "// " + string(96, '-');

    /* write auxiliary stuff to the fuzzer */
    ofs << delim << "\n"
        << substitute(banner,  P("$[ver]$", CURRENT_VERSION),
                               P("$[lib]$", ctx->libPath),
                               P("$[opt1]$", opt1),
                               P("$[opt2]$", opt2),
                               P("$[opt3]$", opt3),
                               P("$[issue]$", ctx->dumpIssues()),
                               P("$[date]$", now())) << "\n"
        << delim << "\n"
        << substitute(headers, P("$[incl]$", fixIncludes())) << "\n"
        << delim << "\n"
        << substitute(globals, P("$[pred]$", pred.str()), P("$[glo]$", glo.str()),
                               P("$[funcs]$", funcs.str())) << "\n"
        << delim   << "\n"
        << kperm   << "\n\n\n"
        << delim   << "\n"
        << eatdata << "\n\n\n"
        << delim   << "\n";


    /* clear potential leftovers of $[func]$ */
    body = substitute(body, P("$[func]$", "")) + "\n";


    // If minEat and maxEat are too close, it will take time for fuzzer to 'guess' the right
    // input size and pass the size check at the beginning of LLVMFuzzerTestOneInput.
    // Thus we increase the value of $[max_total]$ a little bit.

    /* write main()'s body */
    ofs << substitute(mainDecl, P("$[min_total]$", minEat), P("$[max_total]$", maxEat+1024),
                                P("$[body]$", body)) << "\n\n"
        << delim << "\n";

    ofs.close();


    info(v1) << "Fuzzer sucessfully generated as '" << outfile << "'.\n";


    /* if progressive generation is enabled, try to compile the fuzzer */
    if (ctx->mode == android && (flags & FLAG_PROGRESSIVE)) {
        FILE *fp;


        /* create Android.mk first */
        if (!genMakefile(outfile)) {
            return -1;                              // propagate failure
        }

        info(v0)   << "Compiling (partial) fuzzer...\n";
        remark(v0) << "(in case of an error, try to run me again by specifing "
                   << "the '-no-progressive' option)\n";
        remark(v0) << "Compilation might take while .....\r\r\n";

        /* create a BASH pipe */
        if (!(fp = popen("bash", "w"))) {
            fatal() << "Cannot create BASH pipe.\n";
            return -1;                              // failure
        }


        /* send the appropriate commands to the pipe, in order to compile fuzzer */
        string target = ctx->libRoot + ANDROID_FUZZ_DIR;
        ostringstream cmds;

        cmds << "mkdir --parent "          << ctx->libRoot << ANDROID_FUZZ_DIR << " && "
             << "cp -f " << outfile << " " << ctx->libRoot << ANDROID_FUZZ_DIR << " && "
             << "cp -f Android.mk "        << ctx->libRoot << ANDROID_FUZZ_DIR << " && "
             << "cd "                      << ctx->libRoot << " && "
             << "source build/envsetup.sh &> /dev/null && "
             << "lunch "                   << ANDROID_TARGET_DEV << " &> /dev/null && "
             << "cd "                      << ctx->libRoot << ANDROID_FUZZ_DIR << " && "
             // << "SANITIZE_TARGET='address coverage' mma -j" << ANDROID_MAKE_JOBS
             // << " &> /dev/null;";

             /* DEBUG ONLY: Leave output visible to the user */
             << "SANITIZE_TARGET='address coverage' mm -j" << ANDROID_MAKE_JOBS;// << " &> /dev/null;";


        /* send command(s) to BASH */
        fprintf(fp, "%s\n\n", cmds.str().c_str());

        /* wait & check the result */
        int result = pclose(fp);

        if (!result) {
            info(v0) << "Compilation succeeded!\n";
        } else {
            info(v0) << "Compilation failed. Much Sad."
                     << " Rolling back to discard problematic parts...\n";
        }

        /* return 1 on success and 0 upon compilation failure */
        return result == 0;
    }

    return 1;                                       // success!
}



// ------------------------------------------------------------------------------------------------
// Commit current context (backup everything to rollaback (R_) variables).
// This is needed only when progressive generation is enabled.
//
void Composer::commitContext(string body) {
    info(v3) << "Committing context...\n";

    R_minEat = minEat;
    R_maxEat = maxEat;

    R_glo.str(glo.str());
    R_pred.str(pred.str());
    R_funcs.str(funcs.str());

    R_includes.clear();
    R_includes = includes;

    R_gloDecls.clear();
    R_gloDecls = gloDecls;

    R_body = body;
}



// ------------------------------------------------------------------------------------------------
// Rollback current context by 1 step (restore everything from rollaback (R_) variables).
// This is needed only when progressive generation is enabled.
//
string Composer::rollbackContext(void) {
    info(v2) << "Rolling back context...\n";

    minEat = R_minEat;
    maxEat = R_maxEat;

    glo.str(R_glo.str());
    pred.str(R_pred.str());
    funcs.str(R_funcs.str());

    includes.clear();
    includes = R_includes;

    gloDecls.clear();
    gloDecls = R_gloDecls;

    return R_body;
}



// ------------------------------------------------------------------------------------------------
// Collect all the information from the pools and generate the fuzzer.
//
bool Composer::generate(string outfile, int flags) {

// this MACRO checks whether a function has a valid header. If function doesn't have any
// headers, or if it has a header that is outside of the current library path, then the
// appropriate issue is filed and function is skipped.
#define CHECK_HEADER(NAME)                                                       \
    if (header.find(NAME) == header.end() || (                                   \
            header[NAME].compare(0, ctx->libPath.size(), ctx->libPath) &&        \
            header[NAME].compare(0, ctx->auxLibPath.size(), ctx->auxLibPath))) { \
                                                                                 \
        warning() << "Discarding function '" << NAME                             \
                  << "' due to its bad header...\n";                             \
                                                                                 \
        /* report the appropriate issue */                                       \
        ctx->reportIssue("Header file for function '" + NAME +                   \
            "' not found/is invalid. Function is discarded.");                   \
                                                                                 \
                                                                                 \
        /* skip this function to avoid compilation errors */                     \
        continue;                                                                \
    }


    string body;                                    // main()'s body is placed here
    string fuzzerfile = outfile + "_" + FUZZER_SOURCE_EXTENSION;


    /* before u do anything, check the target architecture */
    ptrTy = flags & FLAG_ARCH64 ? "uint64_t": "uint32_t";


    /* check if progressive generation is enabled */
    if (flags & FLAG_PROGRESSIVE) {
        info(v0) << "Progressive generation is enabled!\n";
        info(v0) << "Trying a test build...\n";

        /* compile an empty fuzzer to make sure that compilation works*/
        if (makeFuzzer(fuzzerfile, flags, "    /* Test Build */") < 1) {
            fatal() << "Test build failed. Switch back to non progressive generation...\n";

            flags &= ~FLAG_PROGRESSIVE;             // clear progressive flag
        }
    }


    /* write pools to the file */
    for (uint16_t i=0; i<ctr; ++i) {

        /*
         * TODO: If a function is discarded, what should happen with subsequent
         *       arguments that are dependent on function's return value?
         *
         * UPDATE: Can this really happen?? I.e., an external module uses a discarded function???
         */

        /* Commit current body, as progressive generation, may drop all functions from the pool */         
        commitContext(body);      


        /* when pool contains only 1 function, don't create permutation loop */
        if (pool[i].size() == 1) {
            /* check if header is valid */
            CHECK_HEADER(pool[i].front()->name);

            info(v1) << "Adding function '" << pool[i].front()->name << "' to the pool.\n";

            /* get include file */
            includes.insert(header[pool[i].front()->name]);

            /* generate code to fuzz this function */
            couple d = makeCall(pool[i].front(), i);

            body += tab( substitute(singlePool,
                                    P("$[func]$", d.first + d.second),
                                    P("$[id]$", i)) );


            /* if progressive generation is enabled, compile "so-far" fuzzer */
            if (flags & FLAG_PROGRESSIVE) {
                if( makeFuzzer(fuzzerfile, flags, body) < 1) {    
                    body = rollbackContext();       // rollback changes, as fuzzer doesn't compile
                } else {
                    commitContext(body);            // fuzzer is ok. Commit changes
                }
            }

        /* for >1 functions, do the k-th permutation trick */
        } else if(pool[i].size() > 1) {
            int j = 0;


            /* due to 64-bit permutation limitation, a pool cannot have too many functions */
            if (pool[i].size() > MAX_FUNCS_PER_POOL) {
                /* it's the responsibility of the analyzer to fix this */
                throw FuzzGenException("generate(): Pool has too many functions");
            }

            /* update minimum input size */
            minEat += NBYTES_FOR_FACTORIAL(pool[i].size());
            maxEat += NBYTES_FOR_FACTORIAL(pool[i].size());

            /* launch a multi-pool call */
            body += tab( substitute(multiPool, P("$[n]$", pool[i].size()), P("$[id]$", i)) );

            // To avoid errors such as "use after free scope", declare local variables 
            // that define dependencies outside of the pool's for loop.
            string poolDecl = "\n";


            /* place all functions from the pool under the same permutation loop */
            for (auto ii=pool[i].begin(); ii!=pool[i].end(); ++ii) {
                /* check if header is valid */
                CHECK_HEADER((*ii)->name);

                info(v1) << "Adding function '" << (*ii)->name << "' to the pool.\n";

                /* get include file */
                includes.insert(header[(*ii)->name]);
                
                /* generate code for current function */
                couple d = makeCall(*ii, i);

                if (d.first != "") {
                    poolDecl += d.first + "\n";     // accumulate all declarations
                }

                if (d.second.back() == '\n') {
                    d.second.pop_back();            // drop last new line
                }

                string call = tab3( substitute(multiPoolCall, P("$[i]$", j++),
                                               P("$[call]$", d.second)) );

                /* don't totally replace $[func]$ to allow further substitutions */
                body = substitute(body, P("$[func]$", call + "$[func]$"));


                /* if progressive generation is enabled, compile "so-far" fuzzer */
                if (flags & FLAG_PROGRESSIVE) {
                    /* clear potential leftovers of $[func]$ */
                    body = substitute(body, P("$[func]$", ""));// + "\n";

                    if (makeFuzzer(outfile, flags, body) < 1) {
                        body = rollbackContext();   // rollback changes, as fuzzer doesn't compile
                    } else {
                        commitContext(body);        // fuzzer is ok. Commit changes
                    }
                }

                // NOTE: When we drop a function, the loop counter is not updated That is,
                // a fuzzer might have a pool with 3 functions but the loop bound will be 20.
                // This will only cause some idle iterations, so it's not a big deal
            }



            /* add all declarations outside of function body  */
            body = substitute(body, P("$[decl]$", tab(poolDecl)));

            /* clear potential leftovers of $[func]$ */
            body = substitute(body, P("$[func]$", "")) + "\n";

            /* OPT: $[n]$ might be bigger than j, but it doesn't matter at all */            
        }

        // body += "\n";      
    }


    /* declare buflen */
    glo << "\n\nsize_t buflen = " << ctx->minbuflen << "; /* adaptable buffer length */";


    /* We also need to get the total number of bytes used in buffers. We have:
     *      minEat = ninp + nbufs*minbuflen
     *      maxEat = ninp + nbufs*maxbuflen
     *       
     * where ninp is the total number of bytes for other use (path selection, index fuzzing, etc.)
     * We substitute ninp:
     *      minEat - nbufs*minbuflen = maxEat - nbufs*maxbuflen =>
     *      maxEat - minEat  = nbufs*(maxbuflen - minbuflen)      =>
     *      nbufs = (maxEat - minEat) / (maxbuflen - minbuflen)
     *
     * Neat? ;)
     */
    size_t nbufs = (maxEat - minEat)/(ctx->maxbuflen - ctx->minbuflen),
           ninp  = minEat - nbufs * ctx->minbuflen;

    glo << "\nsize_t nbufs = " << nbufs << "; /* total number of buffers */";
    glo << "\nsize_t ninp  = " << ninp  << "; /* total number of other input bytes */\n";


    if (!nbufs) {
        warning() << "There are no buffers to fuzz in the final Fuzzer! This may be a bug.\n";
    }

    /* don't forget to generate the final fuzzer */
    return makeFuzzer(fuzzerfile, flags, body) >= 0 && genMakefile(outfile);


#undef CHECK_HEADER
}



// ------------------------------------------------------------------------------------------------
// Generate the fuzzer's Makefile to automate the build process.
//
bool Composer::genMakefile(string outfile) {
    set<string> localCincludes;                     // directories for LOCAL_C_INCLUDES
    string      incl;                               // final string of includes


    if (ctx->mode != android) {
        return true;                                // fuzzers for debian don't need an .mk
    }

    ofstream ofs(currDir + "/Android.mk");          // create the Makefile

    info(v0) << "Generating Makefile...\n";

    if (!ofs) {
        fatal() << "Cannot create Makefile.\n";

        remark(v0) << "Error Message: '" << strerror(errno) << "'.\n";      
        return false;
    }

    /* get (the unique) include directories from includes set */
    for (auto ii=includes.begin(); ii!=includes.end(); ++ii) {
        localCincludes.insert(ii->substr(0, ii->find_last_of("/")));
    }

    /* merge directories into a single string */
    for (auto ii=localCincludes.begin(); ii!=localCincludes.end(); incl += *ii++ + " ")
        { }

    if (incl.size() > 0) {
        incl.pop_back();                            // drop last extra space
    }


    /* subsitute Makefile accordingly and write it to the file */
    ofs << substitute(makeFile, P("$[date]$", now()),
                                P("$[incl]$", incl),
                                P("$[fuzzsrc]$", outfile + FUZZER_SOURCE_EXTENSION),
                                P("$[libname]$", ctx->libName),
                                P("$[model]$",  outfile),
                                P("$[libshr]$", ctx->sharedLibs),
                                P("$[libstc]$", ctx->staticLibs));

    ofs.close();

    info(v0) << "Makefile sucessfully generated.\n";

    return true;
}



// ------------------------------------------------------------------------------------------------
// Generate the global Makefile to invoke all fuzzer makefiles
//
bool Composer::generateGlobalMakefile(string outfile, vector<string> &subdirs) {
    ofstream ofs(outfile + "/Android.mk");          // create the global Makefile
    string   makefiles = "";


    info(v0) << "Generating Global Makefile...\n";

    if (!ofs) {
        fatal() << "Cannot create Global Makefile.\n";

        remark(v0) << "Error Message: '" << strerror(errno) << "'.\n";      
        return false;
    }

    /* add each subdirectory to the makefile */
    for (auto ii=subdirs.begin(); ii!=subdirs.end(); ++ii) {
        makefiles += " \\\n";
        makefiles += "    $(LOCAL_PATH)/" + (*ii) + "/Android.mk";
    }

    /* subsitute global Makefile accordingly and write it to the file */
    ofs << substitute(gloMakefile, P("$[date]$",      now()),
                                   P("$[makefiles]$", makefiles));
    ofs.close();

    info(v0) << "Makefile sucessfully generated.\n";

    return true;
}

// ------------------------------------------------------------------------------------------------
