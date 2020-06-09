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
 * compose.h
 *
 * Header file for compose.cpp.
 *
 */
// ------------------------------------------------------------------------------------------------
#ifndef LIBRARY_COMPOSE_H
#define LIBRARY_COMPOSE_H

#include "common.h"                                 // local includes
#include "interwork.h"

#include <iostream>
#include <cstdint>
#include <ctime>
#include <type_traits>
#include <fstream>
#include <string>
#include <vector>
#include <deque>
#include <list>
#include <map>
#include <set>
#include <utility>                                  // for pair & make_pair
#include <algorithm>                                // for max
#include <iterator>

#include <boost/graph/graph_traits.hpp>             // boost libraries
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/topological_sort.hpp>


#define MAX_FUNCS_PER_POOL      20                  // maximum number of functions per pool (up to 20)
#define NO_DISPLACEMENT         0xffff              // invalid struct displacement
#define NO_AMPERSAND            ""
#define AMPERSAND               "&"
#define ANDROID_TARGET_DEV      "aosp_walleye-userdebug"
#define ANDROID_FUZZ_DIR        "/tools/fuzzers/fuzzgen_files"
#define ANDROID_MAKE_JOBS       16
#define STR(x)                  to_string(x)

/*
 * Some libraries like libgsm are strictly implemented in C, so we can't use C++ statements.
 * Uncomment the MACRO below to force generated fuzzer to be in strict C protorype
 */
// #define USE_STRICT_C_PROTOYPE


using namespace std;
using namespace boost;


/* define a 'couple' as a pair of strings */
typedef pair<string, string> couple;


// ------------------------------------------------------------------------------------------------
// * Composer Module *
//
// Generate the C++ fuzzer from the interwork objects.
//
class Composer {
public:
    /* class constructor */
    Composer(string, Context *);

    /* make a new function pool */
    uint16_t mkpool();

    /* push a function object to an existing pool */
    bool push(uint16_t, interwork::APICall *);

    /* get pool's size */
    size_t size(uint16_t);

    /* generate the fuzzer */
    bool generate(string, int);

    /* generate fuzzer's Makefile */
    bool genMakefile(string);

    /* generate global Makefile */
    static bool generateGlobalMakefile(string, vector<string> &);


private:
    Context *ctx;                                   // execution context
    string  currDir;                                // current directory

    vector<list<interwork::APICall*>> pool;         // actual pool
    map<string, string> &header,      &global;      // include headers for each function/global
    map<string, vector<string>>       &inclDep;     // dependencies for include directives
    map<string, bool>                 &tDef;        // all typedef data types

    uint16_t ctr;                                   // internal pool counter
    string   ptrTy;                                 // pointer type (uint32_t/uint64_t)

    /* these variables constitute the "context" of fuzzer's body */
    size_t        minEat, maxEat,                   // min and max number of random input bytes
                  lastEat, maxlastEat;              // last number of  random input bytes (min/max)
    ostringstream glo, pred,                        // string streams for global variables
                  funcs;                            // and function declarations
    set<string>   includes;                         // final set of all #include directives
    set<unsigned> gloDecls;                         // global definitions (don't declare twice)

    map<unsigned, interwork::Argument *> depArg;    // depID -> interwork Argument that is defined    


    /* these variables constitute the "rollback context" */
    size_t        R_minEat, R_maxEat;
    ostringstream R_glo, R_pred, R_funcs;
    set<string>   R_includes;
    set<unsigned> R_gloDecls;
    string        R_body;                           // current main()'s body

    /*
     * NOTE: keeping state variables across functions is not a good programming technique
     *       but this is a quick patch for a special case.
     */
    bool depInit = false;                           // initialize from a dependency
    string depDecl  = "";                           // dependency declarations


    /* save current context */
    void commitContext(string);

    /* rollback current context (1 step behind) */
    string rollbackContext(void);

    /* generate the actuall C++ file (internal function) */
    int makeFuzzer(string, int, string);

    /* cast an interwork type to C++ type */
    string toCppTy(interwork::Argument *);

    /* create a string of N stars */
    inline string star(unsigned);

    /* subscript a name with an index */
    inline string makeName(interwork::Argument *, unsigned);
    inline string makeName(string, unsigned);

    /* cast a dependence ID into a pretty string */
    inline string prettyDep(unsigned, string);

    /* adjust a dependency type */
    bool adjustDependency(interwork::Argument *);

    /* create array indices for iteration */
    inline string iterIndices(unsigned, unsigned);
    inline string iterIndices(unsigned, vector<size_t>);

    /* create array indices for declaration */
    inline string declIndices(unsigned, unsigned);
    inline string declIndices(const vector<size_t>);

    /* create C++ for loops */
    string makeForLoops(unsigned, unsigned, string, string);
    string makeForLoops(unsigned, vector<size_t>, string);

    /* create C++ assignments */
    string makeAssign(string, interwork::Argument *, unsigned);
    string makeAssign(interwork::Element *, unsigned, string, string, string="");

    /* create a random C++ variable */
    string makeVar();

    /* make a string unique by adding some randomness to it */
    void makeUnique(string &);

    /* generate a value that will be assigned to an argument */
    string makeVal(interwork::Argument *);

    /* create a C++ struct initialization (the hacker's way) */
    string makeStruct(interwork::Element *, unsigned, string="");

    /* create a C++ variable declaration */
    couple makeDecl(interwork::Argument *, unsigned);

    /* create a C++ function declaration */
    void makeFuncDecl(interwork::FunctionPtr *);

    /* create a C++ function argument */
    couple makeArgument(interwork::Argument *arg);

    /* create a C++ function call */
    couple makeCall(interwork::APICall *, int);

    /* fix the dependencies between #include headers */
    string fixIncludes();


    // --------------------------------------------------------------------- //
    // Auxiliary functions that are not related w/ fuzzer generation         //
    // --------------------------------------------------------------------- //

    /* variadic template functions for recursively substituting code templates */
    static string substitute(string);

    template<typename T, typename ... couple >
    static string substitute(string, T, couple...);

    /* abbreviations for creating couples */
    static inline couple P(string first, string second) {
        return make_pair(first, second); 
    }
    
    static inline couple P(string first, int second)    {
        return make_pair(first, to_string(second)); 
    }


    /* insert indentations in the code */
    static inline string tab(string s)  {
        /* DEPRECATED */

        return tab(s, 1);
        // return /* "    " + */ substitute(s, P("\n", "\n    "));
    }

    static inline string tab3(string s) {
        /* DEPRECATED */

        return tab(s, 3);
        // return /* "            " + */ substitute(s, P("\n", "\n            "));
    }

    static inline string tab(string s, unsigned n) {
        stringstream ss(s);
        string to, final, indentation;

        /* create the proper indentations first */
        for (unsigned i=0; i<n<<2; ++i, indentation+=" ")
            { }

        /* prepend it to each line */
        while( getline(ss, to, '\n')) {
            if (to.size() > 0)
                final += indentation + to;

            final += "\n";
        }

        return final;
    }
};

// ------------------------------------------------------------------------------------------------
#endif

