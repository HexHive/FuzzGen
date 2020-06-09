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
 * root.h
 *
 * Header file for root.cpp.
 *
 */
// ------------------------------------------------------------------------------------------------
#ifndef LIBRARY_ROOT_H
#define LIBRARY_ROOT_H

#include "common.h"                                 // local includes

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

// ------------------------------------------------------------------------------------------------
// * Root Module *
//
// Find the root functions from from Call Graph (CG). These functions are potentially the API.
//
class Root : public ModulePass {
public:
    static char ID;                                 // pass ID


    /* class constructor */
    Root(set<string> &);

    /* get root functions from call graph */
    const set<string> &getRoots() { return roots; }

    /* function to invoke on each module */
    bool runOnModule(Module &) override;

    /* override these functions from ModulePass */
    virtual void getAnalysisUsage(AnalysisUsage &) const override;
    virtual StringRef getPassName() const override { return "Root"; }

    /* check whether a root function is blacklisted */
    static bool inBlacklist(string);


private:
    static const set<string> badNames;              // "bad" function names
    set<string> &roots;                             // store root function names here
};

// ------------------------------------------------------------------------------------------------
#endif