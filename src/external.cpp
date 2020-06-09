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
 * external.cpp
 *
 * TODO: Write a small description.
 *
 */
// ------------------------------------------------------------------------------------------------
#include "external.h"
#include "analyze.h"
#include "coalesce.h"

/* uncomment if you want to isolate vertex (i.e., fuzzer will have a single vertex from AADG) */
// #define ISOLATE_VERTEX_ID 9

#ifdef ISOLATE_VERTEX_ID                            // DEBUG ONLY
#define ISOLATE_APICALL ISOLATE_VERTEX_ID           // enable isolation mode
#endif




// ------------------------------------------------------------------------------------------------
// Globals
//
char External::ID = 1;


// ------------------------------------------------------------------------------------------------
// Class constructor.
//
External::External(set<string> &libAPI, vector<interwork::APICall*> &intrlObjs, ModulesNG &modsNG, 
        vector<ExternalObj *> &extObjs, Context *ctx) :
        ModulePass(ID), ctx(ctx), uid(0), libAPI(libAPI), modsNG(modsNG), intrlObjs(intrlObjs),
        extObjs(extObjs) {

    info(v0) << "External analysis started.\n";
}



// ------------------------------------------------------------------------------------------------
// Overload this function to specify the required analyses.
//
void External::getAnalysisUsage(AnalysisUsage &au) const {
    au.setPreservesAll();    
    // au.addRequired<PostDominatorTreeWrapperPass>();
}



// ------------------------------------------------------------------------------------------------
// Place (initialized) APICalls into pools.
//
void External::mkPools(ExternalObj *E) {
    info(v1) << "Generating function pools from (flattened) AADG...\n";

    E->calls.clear();                               // clear leftovers
    E->calls.resize(E->layout->pools.size());       // resize vector

    
    /* place APICall objects in 'calls' according to the function pools */
    for (size_t i=0; i<E->layout->pools.size(); ++i) {    
        set<string> hashes;
        hashes.clear();

        for (auto ii=E->layout->pools[i].begin(); ii!=E->layout->pools[i].end(); ++ii) {
            vertex_t v = vertex(*ii, E->layout->AADG);

            /* make sure that APICall is not empty */
            if (E->layout->AADG[v].APICall == nullptr) {
                ctx->reportIssue("AADG node #" + to_string(v) + " has no APICall object.");

                continue; 
            }


            // --------------------------------------------------------------------- //
            //           * Discard identical APICalls from the same pool *           //
            // --------------------------------------------------------------------- //
            string hash = E->layout->AADG[v].APICall->hash(HASHTYPE_STRONG);

            /* check if hash already seen */
            if (hashes.find(hash) != hashes.end()) {
                emph(v1) << "Identical API calls found at pool #" << i 
                         << " (" << E->layout->AADG[v].APICall->name << ")\n";

                // continue;
            } 
            
            hashes.insert(hash);                // and add hash to the set        

            /* all good. Add function to the pool */
            E->calls[i].push_back(E->layout->AADG[v].APICall);
        }
    }
}



// ------------------------------------------------------------------------------------------------
// Perform a "local" external analysis starting from a root function.
//
ExternalObj *External::analyzeLocal(const Module *module, const Function *entry) {
    ExternalObj   *E           = new ExternalObj();
    DominatorTree *CFG_domTree = new DominatorTree((Function &)*entry);    
    map<const Instruction *, unsigned> dID;         // dependence IDs (dIDs)
    


    // --------------------------------------------------------------------- //
    //                        * Make a unique name *                         //
    // --------------------------------------------------------------------- //
    string modName = module->getName();             // cast to string
    size_t pos;


    /* drop path and keep basename only */
    modName = string(basename((char*)modName.c_str()));

    /* drop all extensions (.ll, .tmp) if exist */
    while ((pos = modName.find_last_of(".")) != string::npos) {
        modName = modName.substr(0, pos); 
    }

    /* name the object */
    E->name = modName + "-" + string(entry->getName());

    info(v1) << "External Object name is '"<< E->name << "'\n";
    

    /* if AADG coalescing is enabled, all dIDs must be different */
    if (!(ctx->flags & FLAG_COALESCE)) {
        //uid = 0;                                  // zero counter to avoid very large numbers in 
                                                    // the fuzzer (just for aesthetic reasons)
    }


    // --------------------------------------------------------------------- //
    //                        * Build Fuzzer Layout *                        //
    // --------------------------------------------------------------------- //
    info(v0) << "Building fuzzer layout ...\n";

    E->layout = new Layout(*module, CFG_domTree, libAPI, intrlObjs);

    if (!E->layout->makeAPICallLayout(*entry)) {
        return nullptr;
    }


    if (ctx->visualize) {                           // visualize graphs (if asked)   
        E->layout->visualizeAADG(ctx->fuzzerDir + "/graphs/AADG_" + E->name);
        // E->layout->visualizeDomTree("DomTree");
    }


    // --------------------------------------------------------------------- //
    //                     * Initialize dependence IDs *                     //
    // --------------------------------------------------------------------- //
    info(v0) << "Initializing dependence IDs ...\n";

    /* iterate over every alloca in the module and give each alloca a unique dependence ID */
    for(auto ii=module->begin(); ii!=module->end(); ++ii) {
        for (auto &inst : instructions(*ii)) {  
            if (const AllocaInst *alloca = dyn_cast<AllocaInst>(&inst)) {

                dID[alloca] = uid++;
            }
        }
    }


    // --------------------------------------------------------------------- //
    //                       * Initialize arguments *                        //
    // --------------------------------------------------------------------- //
    info(v0) << "Initializing arguments for AADG nodes ...\n";


    /* create the backward slicing object */
    Backward bwslice(module, libModule, dID, CFG_domTree, libAPI, ctx);

#ifdef ISOLATE_APICALL    
    unsigned vertex_id = ISOLATE_VERTEX_ID;         // specify which node to isolate
#endif    

    
    size_t nodes = E->layout->AADGsize();

    info(v2) << "AADG has " << nodes << " nodes.\n";


    /* iterate over AADG nodes */
    for (vertex_iterator ii=vertices(E->layout->AADG).first; ii!=vertices(E->layout->AADG).second; 
            ++ii) {

        Function::const_arg_iterator arg;
        vertex_t v = vertex(*ii, E->layout->AADG);
        unsigned k;


#ifdef ISOLATE_APICALL                              // if you want to isolate some vertex
        if (v != vertex_id) {
            continue;                               // skip all vertices except one
        }
#endif


        emph(v1) << "================================================== Vertex #" << v << " "
                 << "==================================================\n";

        info(v1) << "Initializing arguments for function:" << *E->layout->AADG[v].inst << "\n";

        const Function     *func    = E->layout->AADG[v].inst->getCalledFunction();
        interwork::APICall *APICall = E->layout->AADG[v].APICall;


        /* show a warning to know what's going on */
        if (APICall->name == "$UNUSED$") {
            warning() << "Function '" << func->getName() << "' has an empty APICall object.\n";

            for (unsigned j=0; j<func->arg_size(); ++j) {
                APICall->args.push_back(new interwork::Argument());
            }
        }

        
        APICall->name   = func->getName();
        APICall->nargs  = func->arg_size();
        APICall->vertex = v;

        /* display a warning, as things can go wrong here :P */
        if (APICall->isVariadic) {
            warning() << "Caution. Function '" << func->getName() << "' is variadic. "
                      << "Things can go wrong here ...\n";

            unsigned argOps = E->layout->AADG[v].inst->getNumArgOperands();


            /* add the (dummy) interwork arguments that are missing */
            while (APICall->nargs < argOps) {
                APICall->args.push_back(new interwork::Argument());

                ++APICall->nargs;
            }
        }


        /* iterate over each argument on the list */
        for (arg=func->arg_begin(), k=0; k<E->layout->AADG[v].inst->getNumArgOperands(); ++k) {

            Value *argVal = E->layout->AADG[v].inst->getArgOperand(k);


            emph(v1) << "--------------------------------------------------"
                     << "--------------------------------------------------\n";
            info(v1) << "Initializing argument #" << k << ": " << *argVal << "\n";

            /* find how argument is initialized (i.e., find the backward slice) */
            if (bwslice.backwardSlicing(const_cast<llvm::Argument*>(arg), argVal,
                                         APICall->args[k], E->layout->AADG[v].inst, 
                                         nullptr, false, 0) == BWSLICE_RETVAL_ERROR) {


                fatal() << "Backward Slicing failed. Much Sad. Discarding current function...\n";

                ctx->reportIssue("Backward Slicing on vertex #" + to_string(v) + " failed. " + 
                                 "(" + E->name + ")");
                

                /* get all dependencies that are defined there (as long as argument exists) */
                if (APICall->args[k]) {
                    set<unsigned> defDeps;

                    E->layout->AADG[v].APICall->getDefDeps(defDeps);

                    for (auto jj=defDeps.begin(); jj!=defDeps.end(); ++jj) {
                        killedDeps.insert(*jj);
                    }
                }

                delete APICall;                     // we don't need you anymore
                E->layout->AADG[v].APICall = nullptr;
                --nodes;

                break;                              // drop the whole API call
            }


            /* print the final interwork argument/elements (DEBUG) */
            info(v1) << "Argument #" << k << " initialized: " << APICall->args[k]->dump() << "\n";

            for (auto ii= APICall->args[k]->subElements.begin(); 
                      ii!=APICall->args[k]->subElements.end(); ++ii) {
                info(v2) << "    Element: " << (*ii)->dump() << "\n";                    
            }        


            /* in variadic functions, llvm::Arguments can be less, so stop increasing at the end */
            if (arg + 1 != func->arg_end()) {
                ++arg;
            }
        }
    }


    /* if all nodes empty drop the whole AADG */
    if (!nodes) {
        delete E;
        return nullptr;
    }


    // Ok something went wrong here and some AADG nodes are empty. The best thing we 
    // can do, is to remove these nodes from the graph and forward all of their edges
    // (to ensure that graph is not disconnected).
    //
    // TODO: This option does not very well here. Instead we leave all empty nodes in
    // the graph and we remove them from the pools at the last stage.
    //
    //
    //  /* drop nodes with NULL APICall objects */
    //  for (vertex_iterator ii=vertices(E->layout->AADG).first;
    //      ii!=vertices(E->layout->AADG).second;) {
    //  
    //      vertex_t v = vertex(*ii, E->layout->AADG);
    //  
    //      if (!E->layout->AADG[v].APICall) {
    //  
    //          warning() << "Node " << v << " is empty!\n";
    //          if (!E->layout->deleteNode(v)) {
    //              fatal() << "Cannot delete node " << v << "!\n";
    //              //++ii;
    //  
    //              // drop the whole AADG
    //              delete E;
    //  
    //              return nullptr;                      
    //          }
    //      } else ++ii;
    //  }


    // --------------------------------------------------------------------- //
    //                       * Analyze Return Values *                       //
    // --------------------------------------------------------------------- //
    emph(v1) << "=================================================="
             << "==================================================\n";

    info(v0) << "Analyzing return values for AADG nodes ...\n";

    /* iterate over AADG nodes */
    for (vertex_iterator ii=vertices(E->layout->AADG).first; ii!=vertices(E->layout->AADG).second; 
            ++ii) {

        vertex_t v = vertex(*ii, E->layout->AADG);
        
        info(v1) << "Analyzing return value for function:" << *E->layout->AADG[v].inst << "\n";


        /* do the actual return value analysis */
        bwslice.retValAnalysis(E->layout->AADG[v].APICall, E->layout->AADG[v].inst);
    }

    info(v0) << "Done.\n";



    // --------------------------------------------------------------------- //
    //                         * Kill Dependencies *                         //
    // --------------------------------------------------------------------- //
    info(v0) << "Killing dependencies that are defined in NULL APICall objects ("
             << killedDeps.size() << ") ...\n";
    
    for (auto jj=killedDeps.begin(); jj!=killedDeps.end(); ++jj) {
        info(v2) << "Killing Dependency: " << *jj << "\n";
    }


    /* iterate over AADG */
    for (vertex_iterator ii=vertices(E->layout->AADG).first; ii!=vertices(E->layout->AADG).second; 
            ++ii) {

        vertex_t v = vertex(*ii, E->layout->AADG);

        /* try to kill each dependency */
        for (auto jj=killedDeps.begin(); jj!=killedDeps.end(); ++jj) { 
            E->layout->AADG[v].APICall->killDep(*jj);
        }
    }



    // --------------------------------------------------------------------- //
    //              * Place (initialized) APICalls into pools *              //
    // --------------------------------------------------------------------- //    
    /* place APICall objects in 'calls' according to the pools */
#ifndef ISOLATE_APICALL                             // normal mode    
    mkPools(E);
#else                                               // isolation mode
    E->calls.resize(E->layout->pools.size());       // resize vector

    if (num_vertices(E->layout->AADG) > vertex_id) {
        E->calls[vertex_id].push_back(E->layout->AADG[vertex_id].APICall);
    }
#endif



    // --------------------------------------------------------------------- //
    //                      * Build Dependence Groups *                      //
    // --------------------------------------------------------------------- //
    emph(v1) << "=================================================="
             << "==================================================\n";

    info(v0) << "Creating Dependence Groups...\n";

    Dependence depGrp(E->layout, dID, ctx);

    depGrp.findIntraDependencies();                 // find intra-procedural dependencies
    depGrp.findInterDependencies();                 // find inter-procedural dependencies
    depGrp.resolveFakeDependencies();               // resolve the fake dependencies
    depGrp.findDefinitions();                       // mark the dependence definitions
    depGrp.assignDependencies();                    // assign dependencies to Argument objects
    depGrp.print();                                 // print all dependencies



    // --------------------------------------------------------------------- //
    //                      * Apply failure heuristic *                      //
    // --------------------------------------------------------------------- //
    if (ctx->flags & FLAG_FAILURE) {
        info(v0) << "Applying failure heuristic...\n";

        /* Add return values to the Dependence Families */       
        for (auto ii=vertices(E->layout->AADG).first; ii!=vertices(E->layout->AADG).second; ++ii) {
            AADGNode node = E->layout->AADG[vertex(*ii, E->layout->AADG)];


            if (node.APICall == nullptr) {
                fatal() << "NULL APICall object on vertex #" << vertex(*ii, E->layout->AADG) << "\n";

                continue;
            }

            info(v1) << "Applying failure heuristic for '" << node.APICall->name << "' ...\n";

            /* apply failure heuristic only when dependencies are defined */
            if (node.APICall->depTy == Dep_def) {
                Failure::findErrorValues(node.inst, node.APICall->vals, node.APICall->ops);
            }
        }
    
    } else {
        info(v0) << "Failure heuristic is disabled...\n";    
    }


    // --------------------------------------------------------------------- //
    //                        * Do something useful *                        //
    // --------------------------------------------------------------------- //
    string   errstr = "";
    unsigned errctr = 0;
    
    /* check which nodes have NULL APICall objects */
    for (auto ii=vertices(E->layout->AADG).first; ii!=vertices(E->layout->AADG).second; ++ii) {
        vertex_t v = vertex(*ii, E->layout->AADG);

        if (E->layout->AADG[v].APICall == nullptr) {
            errstr += to_string(v) + ", ";
            ++errctr;
        }
    }


    if (errctr > 0) {
        /* ok something went wrong :( */
        errstr.pop_back();                          // drop last ", "
        errstr.pop_back();

        warning() << errctr << " vertices have NULL APICall objects: " << errstr << "\n";
        remark(v2) << "This is due to some error in backward slicing.\n";

        if (!continueExecution("Discarding the whole AADG.", ctx)) {
            delete E;
            return nullptr;                         // discard current external module
        }
    }
 

    return E;                                       // return the external object
}



// ------------------------------------------------------------------------------------------------
// Coalesce AADGs. This function takes a vector of AADGs and tries to coalesce as many as it can.
// It selects any 2 AADGs and tries to coalesce them. This process continues until there are no
// more AADGs to coalesce.
//
// To optimize the coalescing between 2 AADGs, we do a neat trick: Node hashes. For each AADG node
// we generate a unique hash that is calculated from its fields. Some fields do not participate
// in the hash. If 2 nodes have the same hash means that they can be coalesced together. All
// fields in the hash remain the same, except the other fields that they get merged together.
//
void External::coalesceAADGs() {
    emph(v2) << "================================================================\n";
    info(v0) << "Coalescing AADGs... " << extObjs.size() << " AADG(s) found.\n";

    map<string, bool> nodeHash;
    string            hash;
    bool              coalesced = true;
    Coalesce          *C = new Coalesce(ctx);


    /* we need at least 2 AADGs to coalesce */
    if (extObjs.size() < 2) {
        return;
    }


    // --------------------------------------------------------------------- //
    //                         * Dump node hashes *                          //
    // --------------------------------------------------------------------- //
    for (unsigned i=0; i<extObjs.size(); ++i) {
        Graph &AADG = extObjs[i]->layout->AADG;
            
        info(v3) << "Node Hashes for AADG '" << extObjs[i]->name << "':\n";

        for (vertex_iterator ii=vertices(AADG).first; ii!=vertices(AADG).second; ++ii) {
            vertex_t v  = vertex(*ii, AADG);

            if (AADG[v].APICall) {
                string hash = C->vertexHash(AADG[v]);

                info(v3) << "    Node #" << v << ": " << hash << "\n";

                if (nodeHash.find(hash) == nodeHash.end()) {
                    nodeHash[hash] = true;
                } else {
                    info(v3) << "    Node is common!\n";
                }
            }
        }
    }


    // --------------------------------------------------------------------- //
    //                          * Do the coalesce *                          //
    // --------------------------------------------------------------------- //
    info(v1) << "Starting coalescing process ...\n";

    while (coalesced) {
        coalesced = false;

        for (unsigned i=0;   i<extObjs.size(); ++i)
        for (unsigned j=i+1; j<extObjs.size(); ++j) {
            ExternalObj *E1 = extObjs[i];
            ExternalObj *E2 = extObjs[j];


            /* if AADGs haven't any common nodes, you can't coalesce them */
            if(!C->haveCommonNode(E1->layout->AADG, E2->layout->AADG)) {
                continue;
            }
        

            /* ok, coalescing is possible */
            info(v1) << "Coalescing '" << E1->name << "' with '" << E2->name << "' ...\n";

            C->coalesce(E1->layout->AADG, E2->layout->AADG);

            info(v1) << "Done.\n";


            E1->name += "+" + E2->name;             // update name
            E1->layout->updateAPICallLayout();      // update layout
            E1->calls.resize(E1->layout->pools.size());                
            
            mkPools(E1);                            // make pools


            if (ctx->visualize) {                   // visualize graphs (if asked)
                E1->layout->visualizeAADG(ctx->fuzzerDir + "/graphs/AADG_" + E1->name);
            }

            extObjs.erase(extObjs.begin() + j);

            // Do not delete extObjs[j], as its objects are used by extObjs[i]

            coalesced = true;
            break;                                  // start all over again (vectors modified)
        }
    }

    info(v0) << "Coalescing completed. " <<  extObjs.size() << " AADG(s) left.\n";

    // --------------------------------------------------------------------- //
    //                         * Update statistics *                         //
    // --------------------------------------------------------------------- //
    ctx->stats.nAADG_coal = extObjs.size();

    for (auto ii=extObjs.begin(); ii!=extObjs.end(); ++ii) {        
        ctx->stats.AADG_coal.push_back(
                Context::AADGInfo((*ii)->layout->AADGsize(), 
                                  (*ii)->layout->AADGedges(), 
                                  (*ii)->name
                )
        );
    }    
}



// ------------------------------------------------------------------------------------------------
// External analysis starts from here.
//
bool External::runOnModule(Module &M) {
   
    /* Analyzer-NG does invokes directly the Pass, so the the last module is not in the vector */     
    if (!modsNG.add(M.getName(), &M)) {             // add the last module to the vector
        fatal() << "Cannot add the last module to the modules vector\n";
        return false;
    }
   

    // --------------------------------------------------------------------- //
    //                            * Build AADGs *                            //
    // --------------------------------------------------------------------- //
 
    /* We have to build an AADG for every root function for every module */

    /* get library module */
    if ((libModule = modsNG.getLibModule()) == nullptr) {
        fatal() << "Cannot find library module\n";
        return false;
    }


    /* iterate over all external modules */
    for (auto ii=modsNG.modules.begin(); ii!=modsNG.modules.end(); ++ii) {
        if ((*ii)->type == MODULE_LIBRARY) {
            
            /* performing an external analysis on the library is catastrophic */
            continue;
        }


        info(v0) << "Analyzing module '" << (*ii)->module->getName() << "' ...\n";

        AnalyzerNG *analyzer = new AnalyzerNG(ctx);
        set<string> rootFuncs;


        /* find all root functions */
        if (!analyzer->quickRun((*ii)->name, new Root(rootFuncs))) {
            fatal() << "Cannot run EnumFunctions module on library '" << "as" << "' file.\n";
            return false;
        }


        /* for each root function build an AADG */
        for(auto jj=(*ii)->module->begin(); jj!=(*ii)->module->end(); ++jj) {        

            if (rootFuncs.find(jj->getName()) != rootFuncs.end()) {            
                info(v1) << "    Analyzing root function '" << jj->getName() << "' ...\n";

                const Function &func = *jj;         // we need this for casting issues


                /* perform a local analysis starting from this root function */
                if (ExternalObj *E = analyzeLocal((*ii)->module, &func)) {
                    extObjs.push_back(E);

                    ctx->stats.nAADG++;
                    ctx->stats.AADG.push_back(
                        Context::AADGInfo(E->layout->AADGsize(), E->layout->AADGedges(), E->name));

                } else {
                    warning() << "Local analysis failed. Much sad :(\n";                    
                }
            }
        }    
    }


    // --------------------------------------------------------------------- //
    //                   * Drop AADGs with a single node *                   //
    // --------------------------------------------------------------------- //
    for (auto ii=extObjs.begin(); ii!=extObjs.end(); ) {
        if ((*ii)->layout->AADGsize() < 2) {
            info(v1) << "Dropping AADG from '" << (*ii)->name << "' as it has a single node.\n";
            

            /* release all objects */
            for (auto jj=(*ii)->calls.begin(); jj!=(*ii)->calls.end(); ++jj) {
                for (auto kk=jj->begin(); kk!=jj->end(); ++kk) {
                    delete *kk;
                }
            }
            
            extObjs.erase(ii);

            delete (*ii)->layout;

        } else ++ii;                                // object is good. Move iterator
    }


    // --------------------------------------------------------------------- //
    //                 * Coalesce as many AADGs as you can *                 //
    // --------------------------------------------------------------------- //
    if (ctx->flags & FLAG_COALESCE) {
        coalesceAADGs();                            // (if needed)
    }


    /* we didn't modify the module, so return false */
    return false;
}

// ------------------------------------------------------------------------------------------------
