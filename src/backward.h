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
 * backward.h
 *
 * Header file for backward.cpp.
 *
 */
// ------------------------------------------------------------------------------------------------
#ifndef LIBRARY_BACKWARD_H
#define LIBRARY_BACKWARD_H

#include "common.h"                                 // local includes
#include "interwork.h"
#include "analyze.h"
#include "root.h"
#include "internal.h"
#include "layout.h"
#include "failure.h"

#include "llvm/Pass.h"                              // llvm includes
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/User.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Analysis/Passes.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/Interval.h"

#include <typeinfo>                                 // c++ includes
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <string>

#include <list>
#include <map>
#include <stack>
#include <vector> 
#include <algorithm>
#include <tuple>
#include <utility>                                  // for pair()

/* backward slicing return values */
#define BWSLICE_RETVAL_ERROR   0x00                 // an error occurred
#define BWSLICE_RETVAL_FAILED  0x01                 // analysis failed but no errors occurred 
#define BWSLICE_RETVAL_SUCCESS 0x02                 // analysis was successful

using namespace std;
using namespace llvm;


// ------------------------------------------------------------------------------------------------
/* status codes for findAlloca() */
enum Status { 
    ST_SUCCESS=0,                                   // no error
    ST_ERROR_CONST_VALUE,                           // a constant value is reached
    ST_ERROR_CALL_FOUND,                            // a call instruction found
    ST_ERROR_MULTIPLE_OPS,                          // instruction has multiple operands
    ST_ERROR_NO_ALLOCA                              // no alloca was found
};


/* store types */
enum StoreOpTy {
    SO_TYPE_INVALID=0,                              // invalid type
    SO_TYPE_STORE,                                  // store instruction
    SO_TYPE_CALL,                                   // call instruction with pass-by-reference
};



// ------------------------------------------------------------------------------------------------
// * Store Operations *
//
// This class holds all store operations to a value.
//
class StoreOp {
public:
    int type = SO_TYPE_INVALID;                     // store operation type

    /* TODO: make this a union */
    const StoreInst *store = nullptr;               // store instruction
    struct Call {
        string funame = "";                         // function name
        int    argNo  = 0;                          // argument number
    } call;


    /* class constructors */
    StoreOp(const StoreInst *store) : type(SO_TYPE_STORE), store(store) { }
    StoreOp(string name, int no)    : type(SO_TYPE_CALL) { call.funame = name; call.argNo = no; }
};



// ------------------------------------------------------------------------------------------------
// * Backward module *
//
// Backward slicing to find the appropriate values for API call arguments.
//
class Backward {
public:
    /* class constructor */
    Backward(const Module *, const Module *libModule, map<const Instruction *, unsigned> &,
            DominatorTree *, set<string> &, Context * );

    /* merge two attributes into a single */    
    static interwork::BaseAttr *mergeAttributes(interwork::BaseAttr *, interwork::BaseAttr *);

    /* static backward slicing */
    int backwardSlicing(llvm::Argument *, const Value *, interwork::Argument* &,
                         const Instruction *, deque<const Instruction *> *, bool, int);

    /* return value analysis */
    void retValAnalysis(interwork::APICall *, const CallInst *);

    /* map alloca's to interwork objects */
    map<const AllocaInst *, interwork::Argument *> allocaMap;


private:
    Context        *ctx;                            // execution context
    const Module   *module;                         // external module
    const Module   *libModule;                      // library module
    set<string>    &libAPI;                         // API functions
    DominatorTree  *CFG_domTree;                    // CFG's dominator Tree
    map<const Instruction *, unsigned> &dID;        // dependence IDs (dIDs)
    
    map<Type *, interwork::Argument *> origIW;      // original interwork objects
    map<Type *, interwork::Argument *> prevIW;      // a previously seen interwork object
    map<Type *, interwork::Argument *> typeToIW;    // LLVM type to interwork elements
    map<string, interwork::Argument *> baseIwArg;   // string to intework elements

    string calledFunc;                              // variable to return data from findAlloca()
    map<const Value *, bool> visitedValues;         // visited values in recursions


    /* find the alloca instruction that corresponds to a Value */
    const AllocaInst *findAlloca(const Value *, deque<const Instruction *> &, int &);

    /* check whether an instruction belongs in some slice */
    bool inSlice(const Instruction *inst, const Instruction *entry);
    
    /* find all store instructions for a given alloca */
    list<StoreOp *> findStores(const AllocaInst *, const Instruction *);

    /* find the corresponding interwork object for a data flow instruction chain */
    interwork::Element *findIWElement(deque<const Instruction *> &, interwork::Argument *,
                                      bool);

    /* extract a constant from Value */
    interwork::BaseAttr *extractConst(const Value *val, interwork::Argument *);

    /* analyze a function (wrapper) that is used as a function pointer */
    bool analyzeWrapper(const Function *, interwork::FunctionPtr* &);

    /* find the argument's prefix (*, &, or none) */
    int findPrefix(deque<const Instruction *>);

    /* adjust argument's type */
    bool adjustType(llvm::Argument *, Type *, interwork::Argument* &, 
                    deque<const Instruction *> &, int);
};

// ------------------------------------------------------------------------------------------------
#endif
