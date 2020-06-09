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
 * infer_api.h
 *
 * Header file for infer_api.cpp.
 *
 */
// ------------------------------------------------------------------------------------------------
#ifndef LIBRARY_INFER_API_H
#define LIBRARY_INFER_API_H

#include "common.h"                             // local includes

#include "llvm/Pass.h"                          // llvm includes
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/Analysis/Passes.h"
#include "llvm/ADT/StringRef.h"

#include <string>
#include <set>


using namespace llvm;
using namespace std;



// ------------------------------------------------------------------------------------------------
// * EnumFunctions Module *
//
// Enumerate (and filter) all functions from the library.
//
class EnumFunctions : public ModulePass {
public:
    static char ID;                                 // pass ID


    /* class constructor */
    EnumFunctions(set<string> &);

    /* function to invoke on each module */
    bool runOnModule(Module &) override;

    /* override these functions from ModulePass */
    virtual void getAnalysisUsage(AnalysisUsage &) const override;
    virtual StringRef getPassName() const override { return "EnumFunctions"; }


private:
    set<string> &funcs;                             // store function names here
};



// ------------------------------------------------------------------------------------------------
// * ExtractPath Module *
//
// Extract the source file path that corresponds to some LLVM module.
//
class ExtractPath : public ModulePass {
public:
    static char ID;                                 // pass ID


    /* class constructor */
    ExtractPath(string &);

    /* function to invoke on each module */
    bool runOnModule(Module &) override;

    /* override these functions from ModulePass */
    virtual void getAnalysisUsage(AnalysisUsage &) const override;
    virtual StringRef getPassName() const override { return "ExtractPath"; }


private:
    string &path;                                   // store source file name here
};



// ------------------------------------------------------------------------------------------------
// * InferAPI module *
//
// Infer library's API by analyzing the whole Android source tree.
//
class InferAPI {
public:
    /* class constructor */
    InferAPI(string, string, string, string, Context *);

    /* infer library's API */
    bool inferAPI();
  
    /* get the results (inferred API) */
    set<string> &getAPI();
    
    /* get the results (external API function set) */
    set<string> &getExtAPI();
    
    /* get the results (all external modules) */
    set<string> &getExternalModules();


private:
    Context *ctx;                                   // execution context
    string  libMod;                                 // library LLVM IR LTO module
    string  libRoot;                                // library root directory
    string  libPath;                                // Android Only: library path in AOSP
    string  consumerDir;                            // root directory with the IR files

    set<string> functions;                          // all library functions (OUT)
    set<string> modules;                            // modules that use these root functions (OUT)
    set<string> APIset;                             // final API
    set<string> extAPIset;                          // API function invoked by external modules
    
    static const set<string> badAPINames;           // "bad" API function names


    /* do the search */
    bool searchModules();

    /* internal (recursive) function for searching */
    bool searchModules(string);

    /* find the full path for an included header */
    string findHeaderPath(string);

    /* extract all #include headers from a source file */
    bool extractHeaders(string, set<string> &);

    /* filter an API function */
    bool filter(string);
};

// ------------------------------------------------------------------------------------------------
#endif