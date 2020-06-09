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
 * external.h
 *
 * Header file for external.cpp.
 *
 */
// ------------------------------------------------------------------------------------------------
#ifndef LIBRARY_EXTERNAL_H
#define LIBRARY_EXTERNAL_H

#include "common.h"                                 // local includes
#include "interwork.h"
#include "analyze.h"
#include "root.h"
#include "internal.h"
#include "layout.h"
#include "dependence.h"
#include "backward.h"
#include "failure.h"


#include "llvm/IR/Module.h"                         // llvm includes
#include "llvm/IR/Function.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Analysis/Passes.h"
#include "llvm/Pass.h"

#include <typeinfo>                                 // c++ includes
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <string>
#include <libgen.h>

#include <vector> 
#include <list>
#include <map>


using namespace std;
using namespace llvm;
    


// ------------------------------------------------------------------------------------------------
// * External Object *
//
// Object that contains all information collected during local analysis.
//
struct ExternalObj {  
    string name;                                    // unique name
    Layout *layout;                                 // API Layout         
    vector<list<interwork::APICall*>> calls;        // interwork object to hold analyzed API calls
};



// ------------------------------------------------------------------------------------------------
// * External module *
//
// Analyze all external modules and extract the usage/dependencies between API calls.
//
class External : public ModulePass {
public:
    static char ID;                                 // pass ID

   
    /* class constructor */
    External(set<string> &, vector<interwork::APICall*> &, ModulesNG &, vector<ExternalObj *> &,
             Context *);

    /* function to invoke on each module */
    bool runOnModule(Module &) override;

    /* override these functions from ModulePass */
    virtual void getAnalysisUsage(AnalysisUsage &) const override;
    virtual StringRef getPassName() const override { return "External"; }


private:
    Context     *ctx;                               // execution context    
    Module      *libModule;                         // LLVM module
    unsigned    uid;                                // unique ID    
    set<string> &libAPI;                            // set of root functions
    ModulesNG   &modsNG;                            // all external modules

    vector<interwork::APICall*> &intrlObjs;         // objects from internal analysis
    vector<ExternalObj *>       &extObjs;           // objects from external analyses

    set<unsigned> killedDeps;                       // killed dependencies


    /* analyze an external module "locally" */
    ExternalObj *analyzeLocal(const Module *, const Function *);

    /* make pools from (flat) AADG */
    void mkPools(ExternalObj *);

    /* coalesce AADGs */
    void coalesceAADGs();
};

// ------------------------------------------------------------------------------------------------
#endif
