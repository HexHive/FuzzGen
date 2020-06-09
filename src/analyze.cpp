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
 * analyze.cpp
 *
 * TODO: Write a small description.
 * TODO: Explain the problem with runOnModule callbacks.
 *
 */
// ------------------------------------------------------------------------------------------------
#include "analyze.h"

using namespace interwork;



// ------------------------------------------------------------------------------------------------

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * *                                                                                           * *
 * *                                     MODULES-NG CLASS                                      * *
 * *                                                                                           * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// ------------------------------------------------------------------------------------------------
// Constructor. No action.
//
ModulesNG::ModulesNG() { 

}



// ------------------------------------------------------------------------------------------------
// Destructor. Deallocate all objects.
//
ModulesNG::~ModulesNG() {
    clear();
}



// ------------------------------------------------------------------------------------------------
// Associate a module name with its type.
//
void ModulesNG::assocType(string modName, int type) { 
    modType[modName] = type;
}



// ------------------------------------------------------------------------------------------------
// Add a new module to the vector of modules.
//
bool ModulesNG::add(string modName, Module *module) { 
    if (modType.find(modName) == modType.end()) {
        return false;                               // cannot find module type
    }


    ModuleObject *modObj = new ModuleObject();      // create the module object

    modObj->name   = modName;                       // and initialize it
    modObj->module = module;
    modObj->type   = modType[modName];

    modules.push_back(modObj);                      // add it to the vector

    return true;
}



// ------------------------------------------------------------------------------------------------
// Clear all modules and free memory/
//
void ModulesNG::clear() { 
    for (auto ii=modules.begin(); ii!=modules.end(); ++ii) {
        delete *ii;                                 // delete objects one by one
    }

    modules.clear();                                // and clear vector as well
}



// ------------------------------------------------------------------------------------------------
// Find the library module in the module vector.
//
Module *ModulesNG::getLibModule() {
    // Assume that a single library module exists  
    for (auto ii=modules.begin(); ii!=modules.end(); ++ii) {
        if ((*ii)->type == MODULE_LIBRARY) {
            return (*ii)->module;
        }        
    }


    return nullptr;                                 // module not found
}



// ------------------------------------------------------------------------------------------------

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * *                                                                                           * *
 * *                                     ANALYZER-NG CLASS                                     * *
 * *                                                                                           * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// ------------------------------------------------------------------------------------------------



// ------------------------------------------------------------------------------------------------
// Constructor. Initialize class members.
//
AnalyzerNG::AnalyzerNG(Context *ctx) : ctx(ctx), pass(nullptr) {
    info(v0) << "Next Generation Analysis started.\n";
}



// ------------------------------------------------------------------------------------------------
// Destructor. Release allocated memory.
//
AnalyzerNG::~AnalyzerNG() {    
    // TODO: This may not needed. Not sure tho
    //
    // /* release all module objects */
    // for (auto ii=modules.begin(); ii!=modules.end(); ++ii) {
    //    delete ii->second;                 
    // }   
}



// ------------------------------------------------------------------------------------------------
// Simply append to the list an IR file name to analyze.
//
void AnalyzerNG::addIR(string IRfile, int type) {
    // no need to check if the same file is added twice 
    filenames.push_back(IRfile);

    modules.assocType(IRfile, type);                // save module type
}



// ------------------------------------------------------------------------------------------------
// Simply save the LLVM Pass object to run in the IR files.
//
void AnalyzerNG::addPass(Pass *pass) {   
    /* if there's already a saved object, abort */
    if (this->pass) {
        throw FuzzGenException("addPass(): Multiple LLVM Passes are not supported");
    }

    this->pass = pass;
}



// ------------------------------------------------------------------------------------------------
// Bootstrap the recursive process to get all Module objects.
//
int AnalyzerNG::run() {
    if (filenames.empty()) {                        // base check
        throw FuzzGenException("run(): No IR files to analyze");
    }

    string filename = filenames.front();            // get the next IR file name to analyze
    filenames.pop_front();

    ctx->status = STATUS_SUCCESS;                   // set status

    info(v2) << "Analyzing '" << filename << "'. #" << filenames.size() << " left.\n";


    if (filenames.size() == 0) {                    // is this the only file to parse?
        return runIntrl(filename, pass, ctx);       // run the actual module pass
    } else {
        /* run the recursive analyzer on the next IR file (just to get the module object) */
        ctx->status &= runIntrl(filename,
                            new AnalyzerNGRecursive(filenames, modules, pass, ctx), ctx);

        return ctx->status;
    }
}



// ------------------------------------------------------------------------------------------------
// Shortcut to run a Pass on a single module
//
int AnalyzerNG::quickRun(string IRfile, Pass *pass) {
    int rval;                                       // return value

 
    addIR(IRfile, MODULE_ANY);
    addPass(pass);
    rval = run();                                   // run the pass

    clear();                                        // cleanup state

    return rval;
}



// ------------------------------------------------------------------------------------------------
// Clear any previous added filenames.
//
void AnalyzerNG::clear() {
    /* do NOT release Pass object (already done) */
    pass = nullptr;                                 // no UAF   
    filenames.clear();                              // drop all filenames

    //  /* release all module objects */
    //   for (auto ii=modules.begin(); ii!=modules.end(); ++ii) {
    //      delete ii->module;
    //  }

    modules.clear();                                // clear dictionary
}





// ------------------------------------------------------------------------------------------------
// The actual function that runs an LLVM Pass on some IR file.
//
int AnalyzerNG::runIntrl(string filename, Pass *pass, Context *myctx) {
    legacy::PassManager passMgr;
    LLVMContext         ctx;
    SMDiagnostic        smd;


    unique_ptr<Module> module(parseIRFile(filename, smd, ctx));
    if (!module) {       
        smd.print(myctx->progName, errs());         // display error
        return STATUS_FAILURE;                      // failure
    }

    /* create and initialize a pass manager */
    PassRegistry &passReg = *PassRegistry::getPassRegistry();
    initializeCore(passReg);
    initializeAnalysis(passReg);

    // Not sure if these are needed:
    //
    // initializeScalarOpts(passReg);
    // initializeIPO(passReg);
    // initializeIPA(passReg);
    // initializeTransformUtils(passReg);
    // initializeInstCombine(passReg);
    // initializeInstrumentation(passReg);
    // initializeTarget(passReg);

    passMgr.add(pass);                              // register pass
    passMgr.run(*module);                           // run pass

    return STATUS_SUCCESS;                          // success
}

// ------------------------------------------------------------------------------------------------
 


// ------------------------------------------------------------------------------------------------

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * *                                                                                           * *
 * *                                ANALYZER-NG RECURSIVE CLASS                                * *
 * *                                                                                           * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// ------------------------------------------------------------------------------------------------



// ------------------------------------------------------------------------------------------------
// Globals
//
char AnalyzerNGRecursive::ID = 7;



// ------------------------------------------------------------------------------------------------
// Constructor. Initialize class members.
//
AnalyzerNGRecursive::AnalyzerNGRecursive(deque<string> &filenames, ModulesNG &modules, Pass *pass,
        Context *ctx) : ModulePass(ID), ctx(ctx), pass(pass), filenames(filenames),
        modules(modules) {

    info(v3) << "Next generation recursive analyzer started.\n";
}

// ------------------------------------------------------------------------------------------------
// Destructor. Just print a message (debugging only).
//
AnalyzerNGRecursive::~AnalyzerNGRecursive() {
    info(v3) << "Next generation recursive analyzer finished.\n";
}


// ------------------------------------------------------------------------------------------------
// Overload this function to specify the required analyses.
//
void AnalyzerNGRecursive::getAnalysisUsage(AnalysisUsage &au) const {
    au.setPreservesAll();

    // we might need these in future
    //
    // au.addRequired<ScalarEvolutionWrapperPass>();
    // au.addRequired<AAResultsWrapperPass>();
    // au.addRequired<AliasAnalysis>();
}



// ------------------------------------------------------------------------------------------------
// The actual callback that runs on the analyzed Module.
//
bool AnalyzerNGRecursive::runOnModule(Module &M) {
    string modname = M.getName().str();             // get module name


    info(v1) << "Callback on module '" << modname << "' started.\n";

    /* no need to check if the same modname appears twice */
 //   modules[ modname ] = &M;                      // save module object
    modules.add(modname, &M);



    /* we know that there's at least 1 file in the deque from runIntrl() */
    string next = filenames.front();                // process next IR file name
    filenames.pop_front();

    info(v1) << "Next IR file to analyze: '" << next << "' ...\n";    

    if (filenames.size() == 0) {                    // if this was the last IR file
        info(v1) << "Reaching the last IR file...\n";

        // status variable, propagates the failure across objects
        ctx->status &= AnalyzerNG::runIntrl(next, pass, ctx);
    } else {
        /* more IR files to analyze. Run recursively the same Pass (self) on the next IR file */
        ctx->status &= AnalyzerNG::runIntrl(next,
                        new AnalyzerNGRecursive(filenames, modules, pass, ctx), ctx);
    }

    info(v1) << "Callback on module '" << M.getName() << "' has finished.\n";


    return false;                                   // we didn't modify the module's IR
}

// ------------------------------------------------------------------------------------------------
