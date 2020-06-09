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
 * dependence.h
 *
 * Header file for dependence.cpp.
 *
 */
// ------------------------------------------------------------------------------------------------
#ifndef LIBRARY_DEPENDENCE_H
#define LIBRARY_DEPENDENCE_H

#include "common.h"                                 // local includes
#include "interwork.h"
#include "root.h"
#include "layout.h"

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

#include <boost/graph/graph_traits.hpp>             // boost libraries
#include <boost/graph/adjacency_list.hpp>
#include <boost/property_map/property_map.hpp>


/* MACRO definitions */
#define INF          9999999                        // infinity
#define RETVAL_ARGNO 99                             // argument number for return values (bogus)


using namespace std;
using namespace llvm;
using namespace boost;    


/* Dependence types */
enum DependenceObjectType {
    DO_invalid = 0x00,                              // invalid argument
    DO_param   = 0x01,                              // parameter
    DO_retval  = 0x02,                              // return value
    DO_def     = 0x10                               // definition
};



// ------------------------------------------------------------------------------------------------
// * Dependence Object *
//
// This class holds all elements needed to describe a dependence.
//
class DepObj {
public:
    const CallInst *call;                           // API call
    const Value    *arg;                            // call's argument (user)
    unsigned       argNo;                           // argument's number (or return value)
    vertex_t       AADGVertex;                      // vertex no in AADG
    unsigned       type;                            // dependence type


    /* class constructor */
    DepObj(const CallInst *call, const Value *arg, unsigned argNo, vertex_t AADGVertex,
           unsigned type) : 
           call(call), arg(arg), argNo(argNo), AADGVertex(AADGVertex), type(type) { }

    /* operator is needed to allow map to compare objects. Use vertex+arg no as index */
    bool operator<(const DepObj &obj) const {
        return ((argNo << 16) | AADGVertex) < ((obj.argNo << 16) | obj.AADGVertex);
    }
};



// ------------------------------------------------------------------------------------------------
// * Dependence module *
//
// This class holds all dependence information across arguments and return values.
//
class Dependence {
public:
    /* class constructor */
    Dependence(Layout *, map<const Instruction *, unsigned> &, Context *);

    /* find intra-procedural dependencies */
    void findIntraDependencies();

    /* find inter-procedural dependencies */
    void findInterDependencies();

    /* resolve the dependencies that may be fake */
    void resolveFakeDependencies();

    /* find the 1st dependency that makes the definition */
    void findDefinitions();

    /* assign dependencies to APICall objects */
    void assignDependencies();

    /* print alloca vectors */
    void print();


private:
    Context                            *ctx;        // execution context
    Layout                             *L;          // fuzzer layout
    Graph                              &AADG;       // Abstract API Dependence Graph 
    map<const Instruction *, unsigned> &dID;        // dependence IDs (dIDs)
    

    /* alloca vector and inverse alloca vector */
    map<const DepObj *, unsigned>         allocaVec;
    map<unsigned, vector<const DepObj *>> allocaIVec;


    /* get the alloca from a store instruction */
    const AllocaInst *getAlloca(const StoreInst *);

    /* find the alloca for some value */
    const AllocaInst *findAlloca(const Value *); 

    /* check whether an alloca can reach another alloca */
    bool allocasReach(const AllocaInst *, const AllocaInst *);

    /* check whether an argument is used uninitialized */
    bool isUsedUninitialized(const AllocaInst *, const CallInst *);

    /* coalesce 2 alloca vectors */
    void coalesceAllocaVec(const CallInst *, unsigned, vertex_t,
                           const CallInst *, unsigned, vertex_t);

};

// ------------------------------------------------------------------------------------------------
#endif
