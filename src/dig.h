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
#ifndef LIBRARY_DIG_H
#define LIBRARY_DIG_H

#include "common.h"                                 // local includes
#include "interwork.h"
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
#include "llvm/IR/TypeFinder.h"
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



// ------------------------------------------------------------------------------------------------
// * Dig module *
//
// Perform a type analysis on some argument
//
class Dig {
public:

    /* class constructor */
    Dig(const Module *, Context *);

    /* class destructor */
    ~Dig();

    /* dig into a type */
    interwork::Argument *digType(Argument &, Type *, bool);    

    /* dig into a return value type */
    interwork::Argument *digRetValType(Type *);

    /* get pure struct type */
    static Type *getStructTy(Type *);

    /* get struct name */
    static string getStructName(Type *);

    /* count pointer indirections for a type */
    static unsigned getStructPtrs(Type *);

    /* get type as a string */
    static string getTypeStr(Type *);

    /* get base type as a string */
    static string getBaseTypeStr(Type *);

    /* strip a fully qualified llvm struct name to get the actual name of the struct */
    static string stripStructName(string);


private:
    Context      *ctx;                              // execution context
    const Module *module;                           // module that pass runs on
    Magic        *magic;                            // the magic pointer (for internal analysis)
    Type         *argTy;                            // original argument type

    map<string, int> visited;                       // visited structs (needed by digInto)
    deque<unsigned>  structOff;                     // element offsets within struct
                                                    // (>1 for nested structs)
    
   
    /* check whether an argument represents an array */
    inline bool isArray(const Argument *);

    /* analyze (recursively) arguments & struct elements */
    bool digInto(Argument *, Type *, interwork::Element *, uint64_t, int, bool);
};



// ------------------------------------------------------------------------------------------------
// * Dig wrapper module *
//
// A thin wrapper around dig module. Although deprecated, I don't want to change the interface.
//
class DigWrapper {
public:
    static char ID;                                 // pass ID


    /* class constructor */
    DigWrapper(interwork::Argument *&, StringRef, unsigned, Type *, bool, Context *);

    /* function to invoke on each module */
    bool runOnModule(const Module *);


private:  
    Context              *ctx;                      // execution context
    interwork::Argument* &iwArg;                    // interwork argument (OUT)
    StringRef            funcName;                  // API function name (IN)
    unsigned             argNo;                     //   and argument number (IN)
    Type                 *type;                     // argument type (IN)
    bool                 doMagic;                   // flag for magic module (IN)
};

// ------------------------------------------------------------------------------------------------
#endif
