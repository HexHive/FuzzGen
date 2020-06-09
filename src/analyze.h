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
 * analyze.h
 *
 * Header file for analyze.cpp.
 *
 */
// ------------------------------------------------------------------------------------------------
#ifndef LIBRARY_ANALYZE_H
#define LIBRARY_ANALYZE_H

#include "common.h"                                 // local includes
#include "interwork.h"

#include "llvm/Pass.h"                              // llvm includes
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/CallSite.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/Passes.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Support/SourceMgr.h"

#include <typeinfo>                                 // c++ includes
#include <cstring>
#include <set>
#include <map>


using namespace llvm;
using namespace std;


/* analyzer status */
enum AnalyzerStatus {
    STATUS_FAILURE = 0x00, 
    STATUS_SUCCESS = 0x01
};

/* analyzer status */
enum ModuleType {
    MODULE_ANY      = 0x00,
    MODULE_LIBRARY  = 0x01,
    MODULE_EXTERNAL = 0x02 
};


class AnalyzerNGRecursive;                          // forward declaration



// ------------------------------------------------------------------------------------------------
// * ModulesNG module *
//
// The next generation class for holding and processing all analyzed modules.
//
class ModulesNG {
public:
    struct ModuleObject {                           // module object
        string name;                                // module name
        Module *module;                             // actuall llvm module
        int    type;                                // module type
    };


    /* class constructor */
    ModulesNG();

    /* class destructor */
    ~ModulesNG();

    /* associate a module name with a type */
    void assocType(string, int);

    /* add a module to the list */
    bool add(string, Module *);

    /* get the library module (when there are multiple external ones) */
    Module *getLibModule();

    /* clear all modules */
    void clear();
 

// private:
    vector<ModuleObject *> modules;                 // the actual modules
    map<string, int>       modType;                 // module type

};



// ------------------------------------------------------------------------------------------------
// * AnalyzerNG module *
//
// The next generation analyzer that analyze multiple IR modules at once
//
class AnalyzerNG {
public:
    ModulesNG modules;                              // analyzed modules (next generation)


    /* class constructor */
    AnalyzerNG(Context *);

    /* class destructor */
    ~AnalyzerNG();

    /* add an IR file to analyze */
    void addIR(string, int);

    /* add an LLVM Pass to run on the analyzed files */
    void addPass(Pass *);

    /* run the Pass on all IR files */
    int run();

    /* quickly run a Pass on a single IR file */
    int quickRun(string, Pass *);

    /* clear analyzer's state */
    void clear();


private:
    Context       *ctx;                             // execution context
    deque<string> filenames;                        // IR file names
    Pass          *pass;                            // Pass object
    

    /* the actual function that runs the Pass on some IR files */
    static int runIntrl(string, Pass *, Context *);

    /* AnalyzerNGRecursive is a friend class so it can access runIntrl() */
    friend class AnalyzerNGRecursive;
};


 
// ------------------------------------------------------------------------------------------------
// * AnalyzerNGRecursive module *
//
// The recursive version of the next generation analyzer that assists the whole process.
//
class AnalyzerNGRecursive : public ModulePass {
public:
    static char ID;                                 // Pass ID
 
    /* function to invoke on each module */
    bool runOnModule(Module &) override;

    /* override these functions from ModulePass */
    virtual void getAnalysisUsage(AnalysisUsage &) const override;
    virtual StringRef getPassName() const override { return "analyzer-ng"; }

    /* class constructor */
    AnalyzerNGRecursive(deque<string> &, ModulesNG &, Pass *, Context *);

    /* class destructor */
    ~AnalyzerNGRecursive();
  

private: 
    Context           *ctx;                         // execution context
    Pass              *pass;                        // Pass object
    deque<string>     &filenames;                   // IR file names
    ModulesNG         &modules;                     // analyzed module objects
};

// ------------------------------------------------------------------------------------------------
#endif
