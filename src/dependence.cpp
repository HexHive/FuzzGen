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
 * dependence.cpp
 *
 * This file is responsible for finding the dependencies across arguments and return values of the
 * API calls. Essentially, it starts from AADG (1 node per argument/return value, no edges) and
 * gives a unique "color" to each argument. As dependencies pop up, graph is recolored, so all
 * participants in a dependence have the same color. At the end, each strong connected component
 * in the graph will have nodes of the same color and these will be our dependencies.
 *
 * To simplify things however, instead of colors we use unique IDs and instead of graphs we use 
 * vectors (allocaVec).
 *
 */
// ------------------------------------------------------------------------------------------------
#include "dependence.h"



// ------------------------------------------------------------------------------------------------
// Class constructor.
//
Dependence::Dependence(Layout *L, map<const Instruction *, unsigned> &dID, Context *ctx) :
        ctx(ctx), L(L), AADG(L->AADG), dID(dID) {

}



// ------------------------------------------------------------------------------------------------
// Store instructions write to memory. To write to memory you should allocate it first. Thus,
// the 2nd operand of each store instruction should come from an alloca.
//
// The reason that we can do that is due to Single Static Assignment (SSA).
//
const AllocaInst *Dependence::getAlloca(const StoreInst *store) {
    if (const AllocaInst *alloca = dyn_cast<AllocaInst>(store->getOperand(1))) {
        return alloca;
    }

    fatal() << *store << "\n";
    fatal() << *store->getOperand(1) << "\n";

    throw FuzzGenException("getAlloca(): Store's operand is not an alloca");
}



// ------------------------------------------------------------------------------------------------
// Find the alloca (if exists) for some value, by traversing the data flow graph backwards.
// (simplified version from the one in backward.cpp)
//
const AllocaInst *Dependence::findAlloca(const Value *val) { 
    if (dyn_cast<Constant>(val)) {                  // constant value?
        return nullptr;                             // analysis failed
    }


    /* while value is an instruction, follow the operand chain */
    while (const Instruction *inst = dyn_cast<Instruction>(val)) {
    
        /* instructions whitelist (make sure is consistent with bakzzzz.cpp:findAlloca()) */
        if (!dyn_cast<AllocaInst>       (val) &&
            !dyn_cast<GetElementPtrInst>(val) &&
            !dyn_cast<BitCastInst>      (val) &&
            !dyn_cast<ZExtInst>         (val) &&
            !dyn_cast<SExtInst>         (val) &&
            !dyn_cast<ICmpInst>         (val) &&
            !dyn_cast<LoadInst>         (val) &&
            !dyn_cast<TruncInst>        (val)) {
                return nullptr;
        }
            

        /* check whether current value is an alloca? */
        if (const AllocaInst *alloca = dyn_cast<AllocaInst>(val)) {
            return alloca;                          // alloca found!
        }

        /* for calls, we can't just "jump" from the return value chain to the arguments' chains */
        else if (dyn_cast<CallInst>(val)) {
            return nullptr;                         // analysis failed
        }


        /* When inst->getNumOperands() > 1, it may be possible to have two operands
         * that are Instructions, so they can end up in two different alloca's. In
         * that case we need to inspect the Instruction and decide which operand to
         * follow.
         */
        unsigned n_inst_ops = 0;                    // number of Instruction operands

        for (auto &ii : inst->operands()) {         // for each operand
            if (dyn_cast<Instruction>(ii)) {        // if it's an instruction
                val = ii;                           // use it as the next value
                ++n_inst_ops;
                break;
            }

            /* otherwise, ii can be a constant value */
        }

        /* if there are no more instructions, stop. No alloca has found. */
        if (!n_inst_ops) break;

        /* if we had encounter >1 instruction operands, we have a problem */
        else if (n_inst_ops > 1) {
            return nullptr;
        }
    }

    return nullptr;                                 // failure. Can't find alloca
}



// ------------------------------------------------------------------------------------------------
// Check whether an alloca instruction can reach another alloca. The idea is to start from the 1st
// alloca and recursively follow the users, the users of users and so on. When we hit an call,
// we have an alias, so we "switch" allocas and we recursively continue search from the new alloca
// till we reach the final alloca.
//
bool Dependence::allocasReach(const AllocaInst *alloca1, const AllocaInst *alloca2) {
    map<const Instruction *, const Instruction *> parent;
    stack<const Instruction*>                     S;


    parent[alloca1] = nullptr;                      // root has no parent
    S.push(alloca1);                                // add alloca to the stack

    /* do a regular DFS on "users of users", i.e. dataflow analysis */
    while (!S.empty()) {
        const Instruction *inst = S.top();          // get top instruction
        S.pop();


        /* check if Argument is being used inside another function */
        if (const CallInst *call = dyn_cast<CallInst>(inst)) {
            const Function *callee = call->getCalledFunction();
            const Use      *a1;
            const Argument *a2;

            if (!callee) continue;                  // skip empty callees


            /* do a basic alias analysis */

            /* find the alloca inside the callee that holds the current alloca */
            for (a1=call->op_begin(), a2=callee->arg_begin(); a1!=call->op_end() &&
                    a2!=callee->arg_end(); ++a1, ++a2) {

                /* check if argument's use matches with the parent */
                if (a1->get() == parent[inst]) {

                    /* argument found. Look at argument's users (it must have >1 store) */
                    for (const User *usr : a2->users()) {
                        if (const StoreInst *st = dyn_cast<StoreInst>(usr)) {
                            /* Before we coalesce the 2 allocas we have to make sure that
                             * they are of the same type. 
                             *
                             * One exception here is the casting from void* (i8*)
                             */
                            string allocaTy1 = Dig::getBaseTypeStr(alloca1->getType()),
                                   allocaTy2 = Dig::getBaseTypeStr(getAlloca(st)->getType());

                            if (allocaTy1 == allocaTy2 || allocaTy2 == "i8") {
                                
                                /* if the final alloca found, stop */
                                if (getAlloca(st) == alloca2) {
                                    return true;
                                }


                                /* otherwise we have an alias. Keep searching from the new alloca */
                                if (allocasReach(getAlloca(st), alloca2) == true) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }

        // TODO: Come back to that
        //
        // /* store instructions (check whether is modified before it gets reused) */
        // else if (const StoreInst *st = dyn_cast<StoreInst>(inst)) {
        //     fatal() << "WHAT* " << * st << "\n";
        //     exit(0);
        // }


        /* look at the users of current instruction and push them on the stack */
        for (Value::const_user_iterator usr=inst->user_begin(); usr!=inst->user_end(); ++usr) {
            const Instruction *nxt = dyn_cast<Instruction>(*usr);

            if (parent.find(nxt) != parent.end()) {
                continue;                           // skip visited nodes
            }

            parent[nxt]  = inst;                    // set parent
            S.push(nxt);                            // push it on the stack
        }
    }

    return false;                                   // nope. Allocas can't reach
}



// ------------------------------------------------------------------------------------------------
// Check whether the memory of an alloca is used without being initialized till "final"
// instruction.
//
bool Dependence::isUsedUninitialized(const AllocaInst *alloca, const CallInst *final) {
    map<const Instruction *, const Instruction *> parent;
    stack<const Instruction*>                     S;


    parent[alloca] = nullptr;                       // root has no parent
    S.push(alloca);                                 // add alloca to the stack

    /* do a regular DFS on "users of users", i.e. dataflow analysis */
    while (!S.empty()) {
        const Instruction *inst = S.top();          // get top instruction
        S.pop();


        if (inst == final) {
            return true;                            // final reached, no initialization found 
        }


        if (const StoreInst *store = dyn_cast<StoreInst>(inst)) {
            const Function *func       = alloca->getFunction();
            int             paramFound = 0;


            /* if the parameter is stored, ignore it (not an actual value is stored) */
            for (auto arg=func->arg_begin(); arg!=func->arg_end(); ++arg) {
                for (auto use=arg->use_begin(); use!=arg->use_end(); ++use) {
                    if (dyn_cast<Value>(*use) == store->getValueOperand()) {
                        paramFound = 1;
                        break;
                    }
                }   

                if (paramFound) break;              // no reason to search further
            }

            /* store does not store a parameter, so argument gets initialized */
            if (!paramFound) {
                return false;
            }
        }


        /* look at the users of current instruction and push them on the stack */
        for (Value::const_user_iterator usr=inst->user_begin(); usr!=inst->user_end(); ++usr) {
            const Instruction *nxt = dyn_cast<Instruction>(*usr);

            if (parent.find(nxt) != parent.end()) {
                continue;                           // skip visited nodes
            }

            parent[nxt]  = inst;                    // set parent
            S.push(nxt);                            // push it on the stack
        }
    }

    return true;                                    // search space exhausted, no initialization found 
}



// ------------------------------------------------------------------------------------------------
// Coalesce 2 alloca vectors. When an alloca reaches another one, all dependencies from the
// second alloca should get the same ID with the dependencies of the first alloca.
//
void Dependence::coalesceAllocaVec(const CallInst *call1, unsigned argNo1, vertex_t AADGVertex1,
                                   const CallInst *call2, unsigned argNo2, vertex_t AADGVertex2) {

    unsigned ID_1 = INF, ID_2 = INF;                // indices in allocaVec


    /* scan the alloca vector to find the appropriate IDs */
    for (auto ii=allocaVec.begin(); ii!=allocaVec.end(); ++ii) {
        const DepObj *dep = ii->first;

        if (dep->call == call1 && dep->argNo == argNo1 && dep->AADGVertex == AADGVertex1) {
            ID_1 = ii->second;
        } else if (dep->call == call2 && dep->argNo == argNo2 && dep->AADGVertex == AADGVertex2) {
            ID_2 = ii->second;
        }
    }

    /* do a base check */
    if (ID_1 == INF || ID_2 == INF) {
        throw FuzzGenException("coalesceAllocaVec(): AADG vertex not in allocaVec");
    }


    /* coalesce IDs, so all dependence objects have the same ID */
    info(v2) << "    Replacing " << (ID_2 >> 16) << "-" << (ID_2 & 0xffff) 
             << " with "         << (ID_1 >> 16) << "-" << (ID_1 & 0xffff) << "\n";

    for (auto ii=allocaVec.begin(); ii!=allocaVec.end(); ++ii) {
        if (ii->second == ID_2) {
            ii->second = ID_1;                      // update index            
        }
    }
}



// ------------------------------------------------------------------------------------------------
// Find intra-procedural dependencies (i.e., argument dependencies between api calls that belong
// the same function). This is quite simple: all we have to do is to check whether 2 arguments
// have the same alloca. If so and there's no modification between the 2 api calls (so the 
// dependency does not "break") then the same argument is being reused.
//
// Once caveat here is that, it is possible for some argument to appear once in the CFG, but
// multiple times in the AADG (due to the AADG construction). In that case, the same 2 arguments
// from different AADG nodes will have the same alloca and therefore we'll mistakenly associate
// a dependence between them. To fix this problem, we require a dependence to have both the same
// alloca and the same function ID (which is unique per function instance in AADG).
//
// NOTE: We don't care about aliases and other weird cases here.
// 
void Dependence::findIntraDependencies() {    
    allocaVec.clear();                              // clear alloca vector
    allocaIVec.clear();                             // clear inverse alloca vector


    info(v0) << "Intra-procedural dependence analysis started. Building alloca vectors...\n";

    /* iterate over AADG nodes */
    for (vertex_iterator ii=vertices(AADG).first; ii!=vertices(AADG).second; ++ii) {
        vertex_t       v     = vertex(*ii, AADG);
        const CallInst *call = AADG[v].inst;


        /* find the alloca inside the callee that holds the current alloca */
        for (unsigned n=0; n<call->getNumArgOperands(); ++n) {
            const Value      *value  = call->getArgOperand(n);
            const AllocaInst *alloca = findAlloca(value);

            /* TODO: Ensure that argument is not modified between 1st and 2nd use */
           
            if (alloca) {                           // does an alloca really exists?
                DepObj *dep = new DepObj(call, value, n, v, DO_param);

                /* associate (in both directions) argument with it's alloca */
                allocaVec[dep] = (AADG[v].funID << 16) | dID[alloca];
                allocaIVec[(AADG[v].funID << 16) | dID[alloca]].push_back(dep);
            }
        }


        /* check the alloca of the return value as well */
        for (auto user : call->users()) {
            if (const StoreInst *st = dyn_cast<StoreInst>(user)) {
                const AllocaInst *alloca = findAlloca(st->getPointerOperand());

                if (alloca) {
                    DepObj *dep = new DepObj(call, st, RETVAL_ARGNO, v, DO_retval);

                    /* associate (in both directions) return value with it's alloca */
                    allocaVec[dep] = (AADG[v].funID << 16) | dID[alloca];
                    allocaIVec[(AADG[v].funID << 16) | dID[alloca]].push_back(dep);
                }
            }
        }
    }


    info(v0) << "Intra-procedural dependence analysis finished.\n";
    print();                                        // finally print the alloca vector
}



// ------------------------------------------------------------------------------------------------
// Find inter-procedural dependencies (i.e., argument dependencies between api calls that belong
// to different functions). The approach here, is to look for dependencies across functions, by
// inspecting *every* forward edge in AADG (we ignore backward edges as they do not appear in the
// final fuzzer). Therefore, we check whether the alloca from the 1st argument can reach the alloca
// for the 2nd argument.
//
// NOTE: We assume that we don't have dependencies within the same function:
//          api_foo(..., A, B, ...);
//          ...
//          api_foo(..., C, A, ...);
//
//      That is, the i-th argument of api_foo, can't reach the j-th argument of the same function,
//      unless i == j.
//
void Dependence::findInterDependencies() {
    info(v0) << "Inter-procedural dependence analysis started. Extending alloca vectors...\n";

    /* for each edge in AADG */
    for(edge_iterator ii=edges(AADG).first; ii!=edges(AADG).second; ++ii) {
        vertex_t from = source(*ii, AADG),
                 to   = target(*ii, AADG);
        

        info(v2) << "Visiting edge: " << from << " -> " << to << "\n";


        if (AADG[from].funID == AADG[to].funID) {
            info(v2) << "Edge is not inter-procedural.\n";

            continue;
        }
 
        /* we do not care about backward edges (they are not in final fuzzer) */
        if (L->isBackwardEdge(from, to)) { 
            continue;
        }


        /* some edges in AADG are from caller to callee so, we may not found a in path CFG */
        if (!L->isCFGReachable(from, to)) {
            // TODO: This is right, but it screws up the get_version() in HEVC.
//          continue;
        } 


        const CallInst *call1 = AADG[from].inst;    // get call instructions
        const CallInst *call2 = AADG[to].inst;      // 


        // if (call1 == call2) {
        //     continue;
        // }
 
        /* Argument is being used inside another function */
        
        /* find the alloca inside the callee that holds the current alloca */    
        for (unsigned n=0; n<call1->getNumArgOperands(); ++n) {
            for (unsigned m=0; m<call2->getNumArgOperands(); ++m) {

                /* special case */
                if (call1->getName() == call2->getName() && m != n) continue;

    
                /* find alloca's for each argument */
                const AllocaInst *alloca1 = findAlloca(call1->getArgOperand(n)),
                                 *alloca2 = findAlloca(call2->getArgOperand(m));

                /* if an alloca does not exists, or if both allocas are the same, skip */
                if (!alloca1 || !alloca2 || alloca1 == alloca2) {
                    // TODO: If we have transition to the same func with different funcID
                    //       we're gonna miss this case...
                    continue;
                }


                /* type checking: if alloca types are different, discard. Expection: (void*) */
                string allocaTy1 = Dig::getBaseTypeStr(alloca1->getType()),
                       allocaTy2 = Dig::getBaseTypeStr(alloca2->getType());

                if (allocaTy1 != allocaTy2 && allocaTy2 != "i8") {
                    continue;  
                } 

                /* ok, all checks have been passed */
                /* if alloca1 can reach alloca2 in the dataflow graph, we have a dependence */ 
                if (allocasReach(alloca1, alloca2) == 1) {
                    coalesceAllocaVec(call1, n, from, call2, m, to);
                } 

                /* although call1 is before call 2, alloca1 may be after alloca2 */ 
                else if (allocasReach(alloca2, alloca1) == 1) {
                    coalesceAllocaVec(call2, m, to, call1, n, from);    
                }                         

                else {
                    // We have 2 possible scenarios at this point:
                    //  1) alloca1 cannot reach alloca2 (no dependence)
                    //  2) alloca1 reaches alloca2 through an alias
                    // 
                    // If alloca2 is never initialized, then its value should be taken from
                    // somewhere else, so we assume that this is alloca1. Note that, this is
                    // just a heuristic; Although it's very weak it's fine for our evaluation.
                    //

                    // call by reference is an exception 
                    if (isUsedUninitialized(alloca2, call2)) {
                        coalesceAllocaVec(call1, n, from, call2, m, to);
                    }
                }
            }
        }
        

        /* Now check whether the return value of the 1st api call reaches the 2nd api call */
        for (auto user : call1->users()) {            
             if (const StoreInst *st = dyn_cast<StoreInst>(user)) {            
                if (const AllocaInst *alloca1 = findAlloca(st->getPointerOperand())) {

                    for (unsigned m=0; m<call2->getNumArgOperands(); ++m) {                      
                        /* find alloca's for the 2nd argument */
                        const AllocaInst *alloca2 = findAlloca(call2->getArgOperand(m));

                        /* if alloca does not exists, or if both allocas are the same, skip */
                        if (!alloca2 || alloca1 == alloca2) {
                            continue;
                        }


                        /* type checking */
                        string allocaTy1 = Dig::getBaseTypeStr(alloca1->getType()),
                               allocaTy2 = Dig::getBaseTypeStr(alloca2->getType());

                        if (allocaTy1 != allocaTy2 && allocaTy2 != "i8") {
                            continue;  
                        } 

                        /* if return value can reach alloca2, we have a dependence */ 
                        if (allocasReach(alloca1, alloca2) == 1) {
                            coalesceAllocaVec(call1, RETVAL_ARGNO, from, call2, m, to);
                        }  

                        /* although call1 is before call 2, alloca1 may be after alloca2 */ 
                        else if (allocasReach(alloca2, alloca1) == 1) {
                            coalesceAllocaVec(call1, RETVAL_ARGNO, from, call2, m, to);
                        }                         
                    }
                }
            }
        }
    }


    /* Inverse alloca vector is outdated. Re-build it from scratch */
    allocaIVec.clear();                             // clear everything first

    for (auto ii=allocaVec.begin(); ii!=allocaVec.end(); ++ii) {
        allocaIVec[ii->second].push_back(ii->first);
    }


    info(v0) << "Inter-procedural dependence analysis finished.\n";
    print();                                        // finally print the alloca vector
}



// ------------------------------------------------------------------------------------------------
// When 2 arguments have the same alloca it does not strictly mean that they have a dependency:
//      struct foo {int a, b, c;};
//
//      api_call_1(foo.a, foo.b);
//      api_call_2(foo.b, foo.c);
//
// In the above example, all 4 arguments of api_call_1() and api_call_2() have the same alloca.
// However there are no actual dependencies between struct fields. This function spots all "fake"
// dependencies and adjust the alloca vectors accordingly. Note that in this example there's one
// actual dependency between 2nd argument of api_call_1() and the 1st argument of api_call_2().
// In backwardSlicing() we do some preliminary work to mark potentially fake dependencies, but
// here we actually remove them.
//
// The process is quite simple. For each "fake" dependence we find its getelementptr indices,
// and we associate a unique number to them. Then, we update the dID in the allocaVector 
// accordingly.
//
void Dependence::resolveFakeDependencies() {
    static unsigned int   uid = 0;                  // unique ID
    map<string, unsigned> seqID;                    // element sequence -> uid
    string                eltSeq;                   // actual element sequence


    info(v0) << "Resolving fake dependencies ...\n";

    for (auto ii=allocaIVec.begin(); ii!=allocaIVec.end(); ++ii) {
        if (ii->second.size() < 2) {
            continue;                               // ignore dependencies with a single element
        }


        for (unsigned j=0; j!=ii->second.size(); ++j) {
            const DepObj       *dep     = ii->second[j];
            vertex_t           v        = dep->AADGVertex;           
            interwork::APICall *APICall = AADG[v].APICall;


            if (APICall == nullptr) {              
                continue;                           // ignore empty nodes
            }


            /* look for fake dependencies in parameters */
            if (dep->type & DO_param) {
                interwork::Argument *iwArg = APICall->args[dep->argNo];
                
                /* argument has a fake dependency? */ 
                if (iwArg->hasFakeDep) {
                    /* use idx to build element sequence */
                    for (eltSeq = ""; iwArg->parent; eltSeq+=to_string(iwArg->idx) + "-", 
                            iwArg=iwArg->parent) { }

                    /* associate a unique ID to the sequence (if needed) */
                    if (eltSeq != "" && seqID.find(eltSeq) == seqID.end()) {
                        seqID[eltSeq] = ++uid;
                    }

                    /* update dID in allocaVec (use MSB for unique element sequence) */
                    allocaVec[dep] = ii->first + (seqID[eltSeq] << 24);
                }
            }

            /* we can also have them in return values */
            else if (dep->type & DO_retval) {
                if (APICall->retvalSeq != "" && seqID.find(APICall->retvalSeq) == seqID.end()) {
                    seqID[APICall->retvalSeq] = ++uid;
                }

                /* update dID in allocaVec (use MSB for unique element sequence) */
                allocaVec[dep] = ii->first + (seqID[APICall->retvalSeq] << 24);
            }
        }            
    }
    

    /* Inverse alloca vector is outdated. Re-build it from scratch */
    allocaIVec.clear();                             // clear everything first

    for (auto ii=allocaVec.begin(); ii!=allocaVec.end(); ++ii) {
        allocaIVec[ii->second].push_back(ii->first);
    }
}



// ------------------------------------------------------------------------------------------------
// Visitor class that is being used as a callback upon BFS.
//
class BFSVisitor : public bfs_visitor<> {
public:
    /* class constructor */
    BFSVisitor(vector<vertex_t> &visOrder) : visOrder(visOrder) { }

    /* callback that is invoked when a vertex is visited */
    template <class Vertex, class Graph>
    void examine_vertex(Vertex v, Graph &AADG) {
        visOrder.push_back(v);                      // store the order that nodes are visited
    }


private:
    vector<vertex_t> &visOrder;                     // order of visited nodes
};



// ------------------------------------------------------------------------------------------------
// Alloca vector contains groups of arguments that are all dependent to each other. However it does
// not tells us which argument actually defines the dependence. That is one of these argument will
// initialize the dependence and the remaining ones will just use it.
//
// The argument that defines the dependency will be the one that "dominates" the others. 
//
// Instead of looking for dominators, we follow a different approach: We run a BFS on the AADG. The
// argument contained in the node that is visited first, defines the dependence.
//
// UPDATE: BFS may not work as expected. Pool IDs are a better way to infer the order.
//
void Dependence::findDefinitions() {
    vector<vertex_t>        visOrder;               // order of visited nodes
    map<vertex_t, unsigned> visIndex;               // reverse search on visited nodes
    

    info(v0) << "Finding the definitions in dependencies...\n";

    // /* run a BFS find the order of the visited nodes */
    // BFSVisitor V(visOrder);
    // breadth_first_search(AADG, L->AADGroot(), visitor(V));
    //
    //
    // /* build reverse search map */
    // for (unsigned i=0; i<visOrder.size(); ++i) {
    //     visIndex[ visOrder[i] ] = i;
    // }
    //
    // info(v2) << "Order of visited nodes in AADG (through BFS): \n";
    //
    //  for (auto ii=visIndex.begin(); ii!=visIndex.end(); ++ii) {
    //    info(v2) << "AADG vertex " << ii->first << " is visited " << ii->second << "\n";
    // }


    /* iterate over groups in alloca vector */
    for (auto ii=allocaIVec.begin(); ii!=allocaIVec.end(); ++ii) {
        unsigned min     = INF;                     // min index
        DepObj   *minDep = nullptr;                 // dependence object with min index


        if (ii->second.size() < 2) {
            continue;                               // ignore dependencies with a single element
        }

        /* for each group find the argument with the min visIdex[AADGVertex] (linear amortized) */
        // UPDATE: use minimum pool ID (as pools are in order). BFS is can be wrong in some cases.
        for (unsigned j=0; j!=ii->second.size(); ++j) {
            if (min > (unsigned)L->iPools[ii->second[j]->AADGVertex]) {
                min = (unsigned)L->iPools[ii->second[j]->AADGVertex];
                minDep = (DepObj*)ii->second[j];
            }
        }

        minDep->type |= DO_def;                     // git "def" attribute to minimum
    }
}



// ------------------------------------------------------------------------------------------------
// Assign dependencies to APICall objects.
//
void Dependence::assignDependencies() {
    info(v0) << "Assigning Dependencies APICall objects...\n";

    
    for (auto ii=allocaIVec.begin(); ii!=allocaIVec.end(); ++ii) {
        if (ii->second.size() < 2) {
            continue;                               // ignore dependencies with a single element
        }


        for (unsigned j=0; j!=ii->second.size(); ++j) {
            const DepObj       *dep     = ii->second[j];
            vertex_t           v        = dep->AADGVertex;           
            interwork::APICall *APICall = AADG[v].APICall;


            /* this should never happen */
            if (AADG[v].APICall == nullptr) { 
                // throw FuzzGenException("assignDependencies(): AADG node with no APICall object");

                warning() << "AADG node #" << v << " has no APICall object.\n";             
                continue;
            }



            /* get i-th argument from APICall and add it to the dependence group */
            if (dep->type & DO_param) {
                // Due to "Argument reuse" in backwardSlicing(), different Arguments,
                // point to the same interwork object. This can be a problem when we 
                // need to assign different 'depTy' values to the same object. To fix
                // that, we simply "clone" the Argument before we use it.
                // 
                // TODO: This is a quick fix. There can be many stale objects that
                //       we won't deallocate.
                //
                APICall->args[dep->argNo] = APICall->args[dep->argNo]->deepCopy();
                interwork::Argument *arg  = APICall->args[dep->argNo];


                if (dep->type & DO_def) {
                    // logic-OR it as, Dep_init may already be there
                    arg->depTy |= interwork::Dep_def;
                } else {
                    arg->depTy = interwork::Dep_use;
                }

                arg->depID = ii->first << 16;       // assign dependence ID

            } else if (dep->type & DO_retval) {
                /* assign dependence ID to the API Call */
                APICall->depTy = interwork::Dep_def;
                APICall->depID = ii->first << 16;
            }
        }
    }

    info(v0) << "Done. Dependencies assigned successfully.\n";
}



// ------------------------------------------------------------------------------------------------
// Print the alloca vector.
//
void Dependence::print() {
    info(v1) << "Printing alloca vector...\n";
 
    for (auto ii=allocaIVec.begin(); ii!=allocaIVec.end(); ++ii) {
        unsigned dID   = ii->first & 0xffff,        // get dID[alloca]
                 funID = ii->first >> 16;           // and function ID


        if (ii->second.size() < 2) {
            continue;                               // ignore dependencies with a single element
        }


        info(v1) << "Alloca #" << funID << "-" << dID << ":\n";

        for (auto jj=ii->second.begin(); jj!=ii->second.end(); ++jj) {
            string             group("  ");
            raw_string_ostream oss(group);
            const DepObj       *dep = *jj;


            /* pretty print type */
            if (dep->type & DO_retval) {
                oss << "  Return Value";
            } else if (dep->type & DO_param) {
                oss << "  Argument #" << dep->argNo;
            } else {
                 throw FuzzGenException("print(): Invalid Dependence Object type");
            }

            if (dep->type & DO_def) {
                oss << " (D)";                      // mark the definition
            }
               
            oss << " (" << dep->AADGVertex << ") ";
            oss << "of " << dep->call->getFunction()->getName() << ":" << *dep->call;

            info(v1) << oss.str() << "\n";
        }
    }
}

// ------------------------------------------------------------------------------------------------
