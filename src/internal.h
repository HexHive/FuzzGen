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
 * internal.h
 *
 * Header file for internal.cpp.
 *
 */
// ------------------------------------------------------------------------------------------------
#ifndef LIBRARY_INTERNAL_H
#define LIBRARY_INTERNAL_H

#include "common.h"                                 // local includes
#include "interwork.h"
#include "dig.h"
#include "magic.h"

#include "llvm/Pass.h"                              // llvm includes
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/User.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Analysis/Passes.h"

#include <typeinfo>                                 // c++ includes
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <list>
#include <map>
#include <stack>
#include <deque>


using namespace std;
using namespace llvm;


/* analysis mode */
enum AnalysisMode {
    ANALYZE_SINGLE = 0x00,                          // analyze a single function
    ANALYZE_ALL                                     // analyze all functions in LTO module
};



// ------------------------------------------------------------------------------------------------
// * Internal module *
//
// Analyze each function from the exported API and generate the appropriate interwork objects.
//
class Internal : public ModulePass {
public:
    static char ID;                                 // pass ID


    /* class constructors */
    Internal(set<string> *, vector<interwork::APICall*> *, Context *);
    Internal(string, interwork::APICall *, Context *);


    /* class destructor */
    ~Internal();

    /* function to invoke on each module */
    bool runOnModule(Module &) override;

    /* override these functions from ModulePass */
    virtual void getAnalysisUsage(AnalysisUsage &) const override;
    virtual StringRef getPassName() const override { return "Internal"; }


private:
    Module  *module;                                // module that pass runs on
    Context *ctx;                                   // execution context
    int     mode;                                   // analysis mode

    /* mode: all */
    set<string>                 *libAPI = nullptr;  // function set to analyze
    vector<interwork::APICall*> *calls  = nullptr;  // analyzed functions (interwork objects)   

    /* mode: single */
    string             libcall = "";                // function to analyze
    interwork::APICall *call   = nullptr;           // analyzed function (interwork objects)   
};


// ------------------------------------------------------------------------------------------------
#endif
