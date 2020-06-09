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
 * internal.cpp
 *
 * TODO: Write a small description.
 *
 * TODO: I want to deprecate this module.
 *
 */
// ------------------------------------------------------------------------------------------------
#include "internal.h"



// ------------------------------------------------------------------------------------------------
// Globals
//
char Internal::ID = 1;



// ------------------------------------------------------------------------------------------------
// Class constructor for analyzing all API functions. Simply initialize class members.
//
Internal::Internal(set <string> *libAPI, vector<interwork::APICall*> *calls, Context *ctx) :
        ModulePass(ID), ctx(ctx), libAPI(libAPI), calls(calls) {

    string F;


    if (libAPI->size() < 1) {                       // is there any to analyze?
        warning() << "There are no functions to analyze!\n";

        throw FuzzGenException("Empty API");        // abort
    }


    for (auto ii=libAPI->begin(); ii!=libAPI->end(); F+=*ii++ + "(), ")
        { }

    F.pop_back();                                   // drop last comma
    F.pop_back();

    info(v0) << "Internal analysis started.\n";
    info(v1) << "Functions to analyze: " << F << "\n";


    mode = ANALYZE_ALL;
}



// ------------------------------------------------------------------------------------------------
// Class constructor for analyzing a single API function. Simply initialize class members.
//
Internal::Internal(string libcall, interwork::APICall *call, Context *ctx) :
        ModulePass(ID), ctx(ctx), libcall(libcall), call(call) {

    info(v0) << "Internal analysis started.\n";
    info(v1) << "Function to analyze: " << libcall << "\n";


    mode = ANALYZE_SINGLE;
}



// ------------------------------------------------------------------------------------------------
// Class destructor.
//
Internal::~Internal(void) {
    // TODO: release allocated objects
}



// ------------------------------------------------------------------------------------------------
// Overload this function to specify the required analyses.
//
void Internal::getAnalysisUsage(AnalysisUsage &au) const {
    au.setPreservesAll();

    // we might need these in future
    //
    // au.addRequired<ScalarEvolutionWrapperPass>();
    // au.addRequired<AAResultsWrapperPass>();
    // au.addRequired<AliasAnalysis>();
}



// ------------------------------------------------------------------------------------------------
// Analysis starts from here. Analyze all arguments for each API function.
//
bool Internal::runOnModule(Module &M) {
    module = &M;                                    // store module as a private member
    
    /* iterate over each functions */
    for(Module::reverse_iterator ii=M.rbegin(); ii!=M.rend(); ++ii) {
        Function &func   = *ii;
        bool     discard = false;                   // function is not discarded (yet)


        /* check whether function is in API */
        switch (mode) {
          case ANALYZE_ALL:                         // analyze all API functions
            if (!libAPI->count(func.getName())) {
                continue;                           // count is zero => function isn't in the set
            }
            break;

          case ANALYZE_SINGLE:                      // analyze a specific function
            if (libcall != func.getName()) {
                continue;
            }
        }

        info(v0) << "================================ Analyzing '" << func.getName() 
                 << "' ================================\n";


        interwork::APICall *call = new interwork::APICall();
        call->name = func.getName();

        /* get number of arguments */
        call->nargs = func.arg_size();


        /* what about variadic functions? External analysis will reveal the variadic arguments */
        if (func.isVarArg()) {
            warning() << "Variadic functions can be problematic but FuzzGen will do its best :)\n";

            call->isVariadic = true;                // mark function as variadic            
        }



        Dig *dig = new Dig(module, ctx);

        /* return values are handled exactly as arguments */
        call->retVal = dig->digRetValType(func.getReturnType());


        /* iterate through each argument and analyze it */
        for (Function::arg_iterator jj=func.arg_begin(); jj!=func.arg_end(); ++jj) {
            interwork::Argument *arg = dig->digType(*jj, nullptr, true);


            if (arg == nullptr) {
                Type *argTy = jj->getType();

                /* create the issue and report it */
                string             type_str;
                raw_string_ostream raw(type_str);   // create an llvm stream

                raw << "Argument analysis on " << jj->getParent()->getName() << "(... ";
                argTy->print(raw);                  // get type as string
                raw << " " << jj->getName() << " ...) failed. Function is discarded.";

                ctx->reportIssue(raw.str());


                discard = true;                     // discard function
                break;
            }

            call->args.push_back(arg);              // store argument's information that


            /* print the internal interwork argument/elements (DEBUG) */
            info(v1) << "Interwork Argument: " << arg->dump() << "\n";

            for (auto ii=arg->subElements.begin(); ii!=arg->subElements.end(); ++ii) {
                info(v2) << "    Element: " << (*ii)->dump() << "\n";                    
            }        

        }


        if (!discard) {
            /* push function to the pool (if it's not discarded) */
            switch (mode) {
              case ANALYZE_ALL:
                calls->push_back(call);             // add call to the vector
                break;

              case ANALYZE_SINGLE:
                this->call = call;                  // we have a unique call

                return false;                       // our job is over now
            }
           
        }
    }


    /* we didn't modify the module, so return false */
    return false;
}

// ------------------------------------------------------------------------------------------------
