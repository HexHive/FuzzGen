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
 * failure.h
 *
 * Header file for failure.cpp.
 *
 */
// ------------------------------------------------------------------------------------------------
#ifndef LIBRARY_FAILURE_H
#define LIBRARY_FAILURE_H

#include "common.h"                                 // local includes

#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/CallSite.h"

#include <string>                                   // c++ includes
#include <vector> 
#include <queue> 


/* The factor that enables failure heuristic */
#define FAILURE_HEURISTIC_FACTOR 4  


using namespace llvm;
using namespace std;



// ------------------------------------------------------------------------------------------------
// * Failure module *
//
// Apply the failure heuristic to identify which API call return values correspond to errors.
//
class Failure {
public:
    /* class constructor (empty; all members are static) */
    Failure() { };

    /* cast an llvm predicate to a C++ operator */
    static string toOperator(int);

    /* find return values that correspond to errors */
    static bool findErrorValues(const CallInst *, vector<uint64_t> &, vector<string> &);


private:
    /* invert a predicate (e.g., ">" to "<=") */
    static int invert(int);

    /* wrapper around countBlocksRecursive() */
    static unsigned blkCnt(const BasicBlock *);

    /* count all the basic blocks that are reachable from a given entry point */
    static bool blkCntRecursive(const BasicBlock *, unsigned &, map<const BasicBlock*, bool> &);

    /* check if failure heuristic holds */
    static bool isFailure(const BranchInst *, const CmpInst *, uint64_t &, int &);

    /* check if a compare instruction is relevant with call's return value */
    static bool isRelevantCmp(const CmpInst *, const CallInst *);
};

// ------------------------------------------------------------------------------------------------
#endif
