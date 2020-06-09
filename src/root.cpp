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
 * root.cpp
 *
 * TODO: Write a small description.
 *
 */
// ------------------------------------------------------------------------------------------------
#include "root.h"
#include "blacklist.h"

#include "llvm/IR/GlobalValue.h"



// ------------------------------------------------------------------------------------------------
// Globals
//
char Root::ID = 0;



// ------------------------------------------------------------------------------------------------
// Constructor. Initialize class members.
//
Root::Root(set<string> &roots) : ModulePass(ID), roots(roots) {
    info(v0) << "Root module started.\n";
}


// ------------------------------------------------------------------------------------------------
// Overload this function to specify the required analyses.
//
void Root::getAnalysisUsage(AnalysisUsage &au) const {
    au.setPreservesAll();
    au.addRequired<CallGraphWrapperPass>();         // ask for call graph results
}


// ------------------------------------------------------------------------------------------------
// Some functions, for some reason, should not be part of the root function set.
//
bool Root::inBlacklist(string name) {
    const string prefix("llvm.");


    /* functions which start with "llvm." should be excluded */
    if (!name.compare(0, prefix.size(), prefix)) {
        return true;
    }

    /* function names that contain '.' can't be part of lib's API */
    if (name.find('.') != string::npos) {
        return true;
    }

    /* function names that contain "bad" names can't be part of API as well */
    for (auto ii=blacklist.begin(); ii!=blacklist.end(); ++ii) {
        /* if function contains a bad name, discard it */
        if (name.find(*ii) != string::npos) {
            return true;
        }
    }


    return false;                                   // function is not blacklisted
}


// ------------------------------------------------------------------------------------------------
// Module pass. Search for root nodes in the Call Graph. Functions that are invoked through
// function pointers, are an issue here, because they have a caller, even though they have no
// incoming edges in the Call Graph.
//
// A quick n' dirty solution is to search for all functions that their addresses are stored in a
// function pointer. A function address that is stored in a function pointer, means that this
// function will probably be invoked at some point (otherwise there's no need to have the function
// pointer). This implies that function has a caller, so it can't be a root. So, we iterate over
// all store intructions, looking functions that are being assigned. However, we can still miss
// some cases here, as we can't determine the values of all function pointers at compile time.
//
bool Root::runOnModule(Module &M) {
    CallGraph &callGraph = getAnalysis<CallGraphWrapperPass>().getCallGraph();
    map<StringRef, bool> fptrs;                     // store functions that used as pointers
    map<StringRef, bool> xrefs_to;                  // indicate whether a function has an XREF to


    info(v1) << "Searching for function pointers and XREFs to...\n";

    /* search the whole module for store & call instructions */
    for (Module::iterator ii=M.begin(); ii!=M.end(); ++ii) {
        for (Function::iterator jj=ii->begin(); jj!=ii->end(); ++jj) {

            /* assume that function has no XREFs to */
            if (xrefs_to.find(ii->getName()) == xrefs_to.end()) {
                xrefs_to[ii->getName()] = false;
            }


            for (BasicBlock::iterator kk=jj->begin(); kk!=jj->end(); ++kk) {

                /* look for function pointers */
                if (const StoreInst *st = dyn_cast<StoreInst>(kk)) {

                    /* a store found. Check if it corresponds to a function pointer */
                    Type *type = st->getOperand(0)->getType();
                    if (type->getTypeID() != Type::PointerTyID) {
                        continue;                   // not a pointer. Skip.
                    }

                    type = dyn_cast<PointerType>(type)->getElementType();
                    if (type->getTypeID() == Type::FunctionTyID) {

                        /* a function pointer has been found*/
                        info(v3) << "Function '" << st->getOperand(0)->getName()
                                 << "' is used as pointer.\n";


                        /* not all function pointers have a known value at compile time */
                        if (st->getOperand(0)->getName() != "") {
                            fptrs[ st->getOperand(0)->getName() ] = true;
                        } else {
                            remark(v3) << "(an empty name means that we don't know the pointer "
                                     << "value at compile time)\n";
                        }
                    }
                }

                /* look for call instructions */
                else if (const CallInst *cl = dyn_cast<CallInst>(kk)) {
                    const Function *callee = cl->getCalledFunction();

                    /* current function invokes another function. It can't be part of the API */
                    if (callee != nullptr) {
                        xrefs_to[callee->getName()] = true;
                    }
                }
            }
        }
    }


    info(v1) << "Done. " << fptrs.size() << " function pointers found.\n";
    info(v1) << "Searching the call graph for root functions...\n";

    // callGraph.print(errs());


    /* search the call graph for root functions */
    for (CallGraph::iterator ii=callGraph.begin(); ii!=callGraph.end(); ++ii) {

        /* iterator's type is FunctionMapTy: map<const Function*, unique_ptr<CallGraphNode>> */
        CallGraphNode *callGraphNode = ii->second.get();
        Function      *func          = callGraphNode->getFunction();


        /* check if node is root (>1, b/c all nodes are children of a "fake" node) */
        if (callGraphNode->getNumReferences() > 1 || func == nullptr) {
            if (func) info(v3) << "  Skipping function '" << func->getName() << "'\n";
            continue;                               // keep only "root" nodes
        }
      
        /* A function with no incoming edges found. This function is probably part of the API */


        // --------------------------------------------------------------------- //
        //                           * Apply filters *                           //
        // --------------------------------------------------------------------- //

        /* Call Graph is imprecise. Use XREFs as a second check */
        if (xrefs_to[func->getName()] == true) {
            info(v3) << "  Function '" << func->getName() << "' has an XREF to, "
                     << "so it's not a root. Skip.\n";

            continue;
        }

        /* check if function is a function pointer */
        if (fptrs.find(func->getName()) != fptrs.end()) {
            info(v3) << "  Function '" << func->getName() << "' is a root, but is also"
                     << " used by a function pointer. Skip.\n";

            continue;
        }

        /* check whether function is blacklisted */
        if (inBlacklist(func->getName())) {
            info(v3) << "  Function '" << func->getName() << "' is a root, but is blacklisted."
                     << " Skip.\n";
            continue;
        }

        /* drop functions without a body */
        if (func->isDeclaration()) {
            info(v3) << "  Function '" << func->getName() << "' does not have a body."
                     << " Skip.\n";
            continue;
        }

        /* drop functions without a body */
        // ii->getLinkage() == GlobalValue::LinkageTypes::ExternalLinkage
        if (!func->hasExternalLinkage()) {
            info(v3) << "  Function '" << func->getName() << "' does not have external linkage "
                     << "(i.e., not accessible from outside). Skip.\n";
            continue;
        }
        

        info(v1) << "  Function '" << func->getName() << "' is a root!\n";


        /* add function to the root set */
        roots.insert(func->getName());
    }

    info(v0) << "Done. " << roots.size() << " root functions found.\n";


    /* we didn't modify the module, so return false */
    return false;
}

// ------------------------------------------------------------------------------------------------
