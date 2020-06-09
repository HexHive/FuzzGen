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
 * magic.h
 *
 * Header file for magic.cpp.
 *
 */
// ------------------------------------------------------------------------------------------------
#ifndef LIBRARY_MAGIC_H
#define LIBRARY_MAGIC_H

#include "common.h"                                 // local includes
#include "interwork.h"

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


#define DISABLE_MAGIC false
#define ENABLE_MAGIC true


/* Set-attribute modes */
enum SetAttrMode { 
    SET_ATTR_MODE_DISABLED = 0,                     // never update attributes
    SET_ATTR_MODE_OFF,                              // temporarily not update attributes
    SET_ATTR_MODE_ON                                // update attributes on every instruction
};



// ------------------------------------------------------------------------------------------------
// * Stack Frame *
// 
// Node object that is used for DFS
//
class StackFrame {
public:
    const Value *inst;                              // current instruction
    StackFrame  *parent;                            // parent instruction
    unsigned    n,                                  // current struct "depth"
                depth;                              // current tree depth (DEBUG only)
    bool        read;                               // set when branch ends with a load after a GEP
    int         mode;

    /* class constructors */
    StackFrame(const Value *v) :
            inst(v), parent(nullptr), n(0), depth(0), read(false), mode(SET_ATTR_MODE_DISABLED) { }

    StackFrame(const Value *v, int m) :
            StackFrame(v) { mode = m; }

    StackFrame(const Value *v, StackFrame *p) :
            inst(v), parent(p), n(p->n), depth(p->depth), read(p->read), mode(p->mode) { }
};



// ------------------------------------------------------------------------------------------------
// * Magic Data *
// 
// A magic function, produces magic data :P
//
template<typename T>
class MagicData {
public:
    int attr;                                       // attributes
    int mode;
    list<T> predefined;                             // values of predefined set (optional)
    

    /* class constructor */
    MagicData() : attr(0), mode(SET_ATTR_MODE_ON) { }

    /* add (logic OR) an attribute  */
    void addAttr(int a) { 
        if (mode == SET_ATTR_MODE_ON) {
            attr |= a; 
        }
    }

    /* set an attribute (clear previous ones) */
    void setAttr(int a) { 
        if (mode == SET_ATTR_MODE_ON) {
            attr = a; 
        }
    }

    /* add a predefined value */
    void addPredefined(T p) { 
        if (mode == SET_ATTR_MODE_ON) {
            predefined.push_back(p); 
        }
    }

    /* check whether a predefined value is in the set */
    bool inPredefined(T p) {
        return find(predefined.begin(), predefined.end(), p) != predefined.end();
    }
};



// ------------------------------------------------------------------------------------------------
// * Magic module *
//
// Perform the internal analysis for each function API (I kept the name "magic" for legacy
// reasons).
//
class Magic {
public:
    /* Class constructor */
    Magic(Context *, deque<unsigned> &);

    /* do the magic (i.e., internal analysis) */
    interwork::BaseAttr *do_magic(Argument &, Type *, string);

    /* clear visited node (needed for recursion */
    void clear();


private:    
    Context                   *ctx;                 // execution context
    static const set<string>  sizeNames;            // common size names    
    deque<unsigned>           &structOff;           // element offsets within struct
                                                    // (>1 for nested structs)    
    int                       analysisTy;           // magic mode (analysis type)
    Type                      *origTy;              // original argument type
    int                       setAttrMode;          // set-attribute mode

    map<const Argument*,   int>  funcVisited;       // visited functions (needed by DF Analysis)
    map<const Value *,     bool> visited;           // visited instructions
    map<const StoreInst *, bool> skippedStores;     // store instructions that should be avoided
    

    /* check whether an argument represents an array */
    inline bool isArray(const Argument &);

    /* get the preceding argument of a given argument */
    inline const Argument &getPreceding(const Argument &) const;

    /* coalesce two magic data objects into one */
    template<typename T>
    inline void coalesce(MagicData<T> *, MagicData<T> *);    

    /* cast magic data to interwork objects */
    template <typename T>
    interwork::BaseAttr *magicToInterwork(MagicData<T> *, string);

    /* basic data flow analysis */
    template<typename T>
    MagicData<T> *dataflowAnalysis(const Argument &, const AllocaInst *, int);

    /* the "magic" function */
    template<typename T>
    MagicData<T> *argSpaceInference(const Argument &, int=0);
};


// ------------------------------------------------------------------------------------------------
#endif
