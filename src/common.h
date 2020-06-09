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
 * common.h
 *
 * This header file contains declarations that are common across all FuzzGen files.
 *
 */
// ------------------------------------------------------------------------------------------------
#ifndef LIBRARY_COMMON_H
#define LIBRARY_COMMON_H

#include "llvm/Support/raw_ostream.h"
#include "llvm/Pass.h"

#include <iostream>
#include <exception>
#include <queue>
#include <string>
#include <map>
#include <set>
#include <ctime>
#include <utility>                                  // for pair & make_pair



/* general definitions */
#define CURRENT_VERSION     "v3.1"                  // fuzzgen's current version
#define DEFAULT_MIN_BUFLEN  32
#define DEFAULT_MAX_BUFLEN  4096
#define DEFAULT_MAX_DEPTH   4

/* analysis flags */
#define FLAG_NONE           0x0000
#define FLAG_ANALYSIS       0x00ff
// #define FLAG_EXTERNAL       0x0100               // DEPRECATED
#define FLAG_PERMUTE        0x0400
#define FLAG_FAILURE        0x0800
#define FLAG_COALESCE       0x1000
#define FLAG_ARCH64         0x2000
#define FLAG_PROGRESSIVE    0x4000
#define OFFSET_INVALID      0xffff

#define FUZZER_SOURCE_EXTENSION "fuzzer.cpp"        // default fuzzer filename


/* MACRO functions */
#define STACK_CLEAR(S)  while (!S.empty()) S.pop()


using namespace llvm;
using namespace std;



// ------------------------------------------------------------------------------------------------
// Enumerations
//

/* verbosity level (3 levels are ok for now) */
enum Verbosity { v0 = 0, v1, v2, v3 };

/* type of analysis */
enum AnalysisType {
    invalid = 0xffff,
    dumb    = 0x0001,                               // DEPRECATED
    basic   = 0x0003,                               // NOT RECOMMENDED
    deep    = 0x0007                                // deep analysis in the target library
};

/* operation mode */
enum OperationMode {
    invalid_mode   = 0xf,                           // invalide mode
    android        = 0x0,                           // synthesize fuzzers for android
    debian         = 0x1,                           // synthesize fuzzers for debian
    dump_functions = 0x2,                           // dump all functions and exit
    dump_api       = 0x3                            // dump library API and exit
};

/* processor architecture */
enum ProcessorArch {
    x86 = 0x0,
    x64 = 0x1
};

/* argument attributes */
enum ArgumentAttributes {
    ATTR_FAILURE    = 0xffff,                       // analysis failed (MSBit is set)

    ATTR_DEAD       = 0x0000,                       // arg is not used
    ATTR_INVARIANT  = 0x0001,                       // arg is not modified
    ATTR_PREDEFINED = 0x0003,                       // arg takes a constant value from a set
    ATTR_RANDOM     = 0x00ff,                       // arg is neither invariant nor predefined
                                                    // (this value should overwrite the other 2)    

    ATTR_ARRAY      = 0x0100,                       // arg is used as an array (pointers ONLY)
    ATTR_ARRAYSIZE  = 0x0200,                       // arg represents buffer size
    ATTR_WRITEONLY  = 0x0400,                       // arg is used to hold output (pointers ONLY)
    ATTR_BYVAL      = 0x0800,                       // arg is passed by value
    ATTR_NULLPTR    = 0x1000,                       // arg is NULL (pointers ONLY)
    ATTR_DEPENDENT  = 0x2000,                       // DEPRECATED. arg depends on another argument
    ATTR_REFERENCE  = 0x4000,                       // DEPRECATED. arg is a reference of another
                                                    // variable
    ATTR_FUNCPTR    = 0x8000                        // arg is a function pointer

    /* more attributes might be added later */
};



// ------------------------------------------------------------------------------------------------
// Global definitions
//

/* set of (name, argument-number) pairs that indicate a "store" through a call by reference */
const set<pair <string, int>> byRefCalls = {
    make_pair("fread",       0),
    make_pair("llvm.memcpy", 0)
    /* ... */
};

/* set of function names that return arrays */
const set<string> allocFam = {
     "malloc", "calloc", "realloc" /* ... */ 
};



// ------------------------------------------------------------------------------------------------
// * Execution Context *
//
// Common stuff shared across various modules
//
class Context {
public:
    const char *progName;                           // program name as it is: argv[0]
    string     libRoot;                             // library root directory (or AOSP root)
    string     libPath;                             // library path in AOSP
    string     libName;                             // name of the library being processed
    string     staticLibs;                          // static libraries for makefile (can be >1)
    string     sharedLibs;                          // shared libraries for makefile (can be >1)
    string     auxLibPath;                          // auxiliary library path in AOSP     
    string     fuzzerDir;                           // directory that generated fuzzers will be
                                                    // stored

    int      mode  = invalid_mode;                  // operation mode
    int      flags = FLAG_NONE;                     // execution flags    
    unsigned minbuflen, maxbuflen;                  // minimum and maximum allowed buffer sizes
    int      maxDepth;                              // maximum recursion depth (for magic module)
    bool     visualize;                             // if true, visualize intermediate graphs
    unsigned seed;                                  // random seed to use for variable names
    bool     yes;                                   // flag to answer yes to all continue prompts


    int status;                                     // general status information

    /* metadata data structs */
    map<string, string>         header, global;     // function and global declarations
    map<string, vector<string>> inclDep;            // include dependencies
    map<string, bool>           tDef;               // typedef declarations                       
    map<string, vector<string>> paramNames;         // parameter names for each function
    map<string, set<string>>    arrayRef;           // array references (from metadata)
    map<string, vector<string>> strFields;          // array references (from metadata)
    map<string, set<string>>    signParam;          // signed parameters (from metadata)
    map<string, set<string>>    constParam;         // const parameters (from metadata)


    /* various information regarding an AADG */
    struct AADGInfo {
        unsigned nodes, edges;                      // total number of nodes and edges 
        string   name;                              // name (module + root function)


        /* class constructor */
        AADGInfo(unsigned nodes, unsigned edges, string name) : 
                nodes(nodes), edges(edges), name(name) { }
    };


    /* various statistics regarding execution */
    struct Statistics {
        unsigned nFuncs;                            // library functions found
        unsigned nAPI;                              // number of API calls
        unsigned nAPIUsed;                          // number of API calls used in external modules

        unsigned nAADG;                             // number of AADGs
        vector<AADGInfo> AADG;                      // number of nodes and edges for each AADG

        /* information after coalescing */
        unsigned nAADG_coal;                        // number of AADGs
        vector<AADGInfo> AADG_coal;                 // number of nodes and edges for each AADG
    } stats;


    /* report an issue */
    void reportIssue(std::string);

    /* dump all issues into a string */
    std::string dumpIssues();


private:
    queue<string> issues;                           // issues to mention in the fuzzer file (we
                                                    // don't use a set b/c we want them to appear
                                                    // in order)
};



// ------------------------------------------------------------------------------------------------
// Function declarations (only)
//
std::string now();                                  // make now() available to all components
bool isSuffix(std::string, std::string);
bool continueExecution(std::string, Context *);



// ------------------------------------------------------------------------------------------------
// Custom exception class.
//
class FuzzGenException : public std::exception {
public:

    /* class constructor */
    FuzzGenException(const char *err) : err(err) { }


    /* override this to return a custom message */
    virtual const char* what() const noexcept override {
        // use noexcept to prevent an another exception to be thrown this moment
        return err;
    }


private:
    const char *err;                                // exception error message
};



// ------------------------------------------------------------------------------------------------
// Derived exception classes for more specific exceptions.
// These classes are useful when we have nested exceptions.
//
class FuzzGenStructException : public FuzzGenException {
public:
    /* class constructors */
    FuzzGenStructException(const char *err) : FuzzGenException(err) { }
};


class FuzzGenPredicateException : public FuzzGenException {
public:
    /* class constructor */
    FuzzGenPredicateException(const char *err) : FuzzGenException(err) { }
};



// ------------------------------------------------------------------------------------------------
// Display various information to the user.
//
class Info {
public:
    /* types of information */
    enum InfoType { STATUS = 0, REMARK, EMPH, WARNING, FATAL };

    static int verbosityLevel;


    Info(int type, int level) : type(type), currLevel(level) { }
    ~Info() { }


    /* overload stream operator to prepend the appropriate label */
    friend raw_ostream& operator<<(raw_ostream& strm, const Info& s) {

        switch (s.type) {
          // ----------------------------------------------------------------------------
          case STATUS:
            if (s.currLevel > verbosityLevel) {     // if verbosity level exceeds current level,
                return nulls();                     // don't print anything
            }

            outs().changeColor(raw_ostream::GREEN, /* bold */ true, /* bg */ false);
            outs() << "[STATUS]";
            break;

          // ----------------------------------------------------------------------------
          case REMARK:
            if (s.currLevel > verbosityLevel) {
                return nulls();
            }

            outs().changeColor(raw_ostream::BLUE, true, false);
            outs() << "[REMARK]";
            break;

          // ----------------------------------------------------------------------------
          case EMPH:
            if (s.currLevel > verbosityLevel) {
                return nulls();
            }

            outs().changeColor(raw_ostream::MAGENTA, true, false);
            outs() << "[STATUS] ";

            /* keep the color changed for the rest of the text */
            outs().changeColor(raw_ostream::GREEN, true, false);
            
            return strm;

          // ----------------------------------------------------------------------------
          case WARNING:
            errs().changeColor(raw_ostream::YELLOW, true, false);
            errs() << "[WARNING]";
            break;

          // ----------------------------------------------------------------------------
          case FATAL:
            errs().changeColor(raw_ostream::RED, true, false);
            errs() << "[ERROR]";
        }

        errs().resetColor();
        errs() << " ";

        return strm;
    }

private:
    int type;
    int currLevel;
};



// ------------------------------------------------------------------------------------------------
/* that's definitely not the best way to do it, but it works */
#define info(level)     outs() << Info(Info::STATUS, Verbosity::level)
#define remark(level)   outs() << Info(Info::REMARK, Verbosity::level)
#define emph(level)     outs() << Info(Info::EMPH, Verbosity::level)
#define warning()       errs() << Info(Info::WARNING, v0)
#define fatal()         errs() << Info(Info::FATAL, v0)

// ------------------------------------------------------------------------------------------------
#endif
