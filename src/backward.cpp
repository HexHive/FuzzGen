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
 * backward.cpp
 *
 * TODO: Write a small description.
 *
 */
// ------------------------------------------------------------------------------------------------
#include "backward.h"



// ------------------------------------------------------------------------------------------------
// Constructor.
//
Backward::Backward(const Module *module, const Module *libModule,
        map<const Instruction *, unsigned> &dID, DominatorTree *domTree, set<string> &libAPI, 
        Context *ctx) : 
        ctx(ctx), module(module), libModule(libModule), libAPI(libAPI), CFG_domTree(domTree), 
        dID(dID) {

    info(v0) << "Backward analysis started.\n";
}
    


// ------------------------------------------------------------------------------------------------
// Follow the data flow chain to find the alloca (if exists) for a given value.
//
const AllocaInst *Backward::findAlloca(const Value *val, deque<const Instruction *> &chain, 
        int &status) {

    chain.clear();                                  // make sure that chain is empty
    
    if (dyn_cast<Constant>(val)) {                  // constant value?
        status = ST_ERROR_CONST_VALUE;
        return nullptr;                             // analysis failed
    }


    /* while value is an instruction, follow the operand chain */
    while (const Instruction *inst = dyn_cast<Instruction>(val)) {
        chain.push_back(inst);                      // add instruction to the chain


        /* check whether current value is an alloca? */
        if (const AllocaInst *alloca = dyn_cast<AllocaInst>(val)) {
            status = ST_SUCCESS;                    // set status variable
            return alloca;                          // alloca found!
        }

        /* for calls, we can't just "jump" from the return value chain to the arguments' chains */
        else if (const CallInst *call = dyn_cast<CallInst>(val)) {
            if (call->getCalledFunction() == nullptr) {
                warning() << "Cannot get called function!\n";

                status = ST_ERROR_NO_ALLOCA;
                return nullptr;                     // we can't get name
            }

            calledFunc = call->getCalledFunction()->getName();
            status     = ST_ERROR_CALL_FOUND;
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
                

                // TODO: Check if it's right to stop on the 1st operand ...
                break;
            }

            /* otherwise, ii can be a constant value */
        }


        /* if there are no more instructions, stop. No alloca has found. */
        if (!n_inst_ops) break;

        /* if we had encounter >1 instruction operands, we have a problem */
        else if (n_inst_ops > 1) {
            status = ST_ERROR_MULTIPLE_OPS;

            return nullptr;
        }
    }


    // chain.clear();                               // keep the chain, it's needed
    status = ST_ERROR_NO_ALLOCA;                    // set status variable

    return nullptr;                                 // failure. Can't find alloca
}



// ------------------------------------------------------------------------------------------------
// Check whether a given instruction "inst" belongs to the slice starting from "entry" (i.e., 
// check if "inst" is *before* "slice"). One way to do this is to check whether "entry" 
// post-dominates "inst":
//      PostDominatorTree &pDomTree = getAnalysis<PostDominatorTreeWrapperPass>().getPostDomTree();
//
// But here, we follow a different approach: We check whether there's a path from "entry" to "inst"
// in the reverse CFG.
//
bool Backward::inSlice(const Instruction *inst, const Instruction *entry) {
    stack<const BasicBlock *> S;
    map  <const BasicBlock *, bool> visited;

    const BasicBlock *start = entry->getParent();
    const BasicBlock *end   = inst->getParent();


    /* check whether both instructions belong in the same basic block */
    if (start == end) {
        /* if "inst" dominates "entry" then it's in the slice (as both are in the same block) */
        return CFG_domTree->dominates(inst, entry);
    }
       

    S.push(start);                                  // alloca on stack
    visited[start] = true;

    /* DFS on reverse CFG */
    while (!S.empty()) {
        const BasicBlock *curr = S.top();           // get top of the stack
        S.pop();


        if (curr == end) {                          // basic block found
            return true;
        }

        /* traverse CFG backwards (follow predecessors) */
        for (const BasicBlock *Pred : predecessors(curr)) {            
            if (visited.find(Pred) != visited.end()) {
                continue;                           // skip visited nodes
            }

            visited[Pred] = true;                   // set parent (&& mark instruction)
            S.push(Pred);                           // push it on the stack
        }
    }   

    return false;
}



// ------------------------------------------------------------------------------------------------
// Do a simple data flow analysis to find all store instructions that write at the memory of a
// given alloca. 
//
list<StoreOp *> Backward::findStores(const AllocaInst *alloca, const Instruction *entryInst) {

    map  <const Instruction *, const Instruction *> parent;
    map  <const Instruction *, const Instruction *> entry;
    stack<const Instruction *> S;                   // stack for recursion
    list <StoreOp *>           stores;              // store instruction reachable from alloca


    info(v2) << "Finding 'store' instructions for: " << *alloca << "\n";
   
    S.push(alloca);                                 // alloca on stack
    parent[alloca] = nullptr;
    entry[alloca]  = entryInst;


    /* do a regular DFS on "users of users" */
    while (!S.empty()) {
        const Instruction *top = S.top();           // get top of the stack
        S.pop();


        /* have we found a store? */
        if (const StoreInst *st = dyn_cast<StoreInst>(top)) {

            /* check if store is in the same slice */
            if (!inSlice(top, entry[top])) {
                continue;                           // not in slice. Discard it
            }

            // make sure that alloca is used as a pointer (store writes to it) 
            // and not as a value
            if (st->getPointerOperand() == parent[top]) {
                info(v2) << "    Store found:" << *top << "\n";

                stores.push_back(new StoreOp(st));
            } 
        
            continue;                               // don't proceed further
        }

        /* have we found a call? */
        else if (const CallInst *call = dyn_cast<CallInst>(top)) {

            /* check if store is in the same slice */
            if (!inSlice(top, entry[top])) {
                continue;                           // not in slice. Discard it
            }

            /* make sure that function is valid */
            if (call->getCalledFunction() == nullptr) {
                warning() << "Cannot get called function!\n";
                continue;                           // we can't get name
            }


            // If the value is passed by reference into a function, it may be set internally
            // so we have an implicit store. Thus, we recursively follow the callee to inspect
            // its store operations.
            string         name    = call->getCalledFunction()->getName();
            const Function *callee = call->getCalledFunction();
            const Use      *a1;
            const Argument *a2;


            info(v3) << "Encounter function '" << name << "' during searching for 'stores'.\n";
 

            /* find the alloca inside the callee that holds the current alloca */
            for (a1=call->op_begin(), a2=callee->arg_begin(); a1!=call->op_end() &&
                    a2!=callee->arg_end(); ++a1, ++a2) {

                if (a1->get() != parent[call]) {    // if argument's use matches with the parent 
                    continue;
                }

                /* if argument is passed by value, we can't have a store inside */
                if (a2->hasByValAttr()) {
                    continue;
                }

                /* argument found. Look at argument's users (it must have >1 store) */
                for (const User *usr : a2->users()) {
                    if (const StoreInst *st = dyn_cast<StoreInst>(usr)) {
                        if (const AllocaInst *alloca = dyn_cast<AllocaInst>(st->getOperand(1))) {
                            
                            emph(v3) << "findStores(): Switch to '" << name << "' ...\n";
                            S.push(alloca);

                            parent[alloca] = nullptr;
                            entry[alloca] = alloca; // entry point gets changed
                        }
                    }
                }

                break;
            }
        

            /* check if function is in the list */
            for (auto ii=byRefCalls.begin(); ii!=byRefCalls.end(); ++ii) {
                if (name.find((*ii).first) != string::npos) {

                    /* name matched. Now check argument (find the argument number) */                      
                    int j = 0;

                    for (auto a1=call->arg_begin(); a1!=call->arg_end(); ++a1, ++j) {                       
                        if (dyn_cast<Value>(a1) == dyn_cast<Value>(parent[call])) {
                            if (j == (*ii).second){
                                /* we have a call-by-reference modification */
                                info(v2) << "    Store through reference found:" << *top << "\n";

                                stores.push_back(new StoreOp(name, j));
                            }

                            break;                  // our job stops here
                        }
                    }
                }
            }
        }


        /* look at the users of current instruction and push them on the stack */
        for (auto ii : top->users()) {
            const Instruction *nxt = dyn_cast<Instruction>(ii);

            if (parent.find(nxt) != parent.end()) {
                continue;                           // skip visited nodes
            }

            parent[nxt] = top;                      // set parent (&& mark instruction)
            entry[nxt]  = entry[top];               // transfer the same entry point
            S.push(nxt);                            // push it on the stack
        }
    }

    return stores;                                  // return all stores found
}



// ------------------------------------------------------------------------------------------------
// Given a deque of instructions (store -> ... -> alloca), find the appropriate interwork element
// that is being accessed. This makes sense only for structs. GetElementPtr instructions that
// correspond to array indices should be ignored and return a nullptr. However in some cases
// we need to return the same element, so we can control this behavior with the 'skipArray' flag.
//
interwork::Element *Backward::findIWElement(deque<const Instruction *> &chain,
        interwork::Argument* arg, bool skipArray=true) {

    interwork::Element *elt = arg;                  // final element to return
    bool foundArray = false;


    /* follow the chain in reverse order (start from alloca) */
    for (auto ii=chain.rbegin(); ii!=chain.rend(); ++ii) {   

        /* GEP instructions - this is a baby "digInto" */
        if (const GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(*ii)) {
            Type *ty = gep->getPointerOperandType();


            /* select the right subElement from current Element */
            for (auto &ii : gep->indices()) {       // check GEP indices

                if (ty->isPointerTy()) {            // pointer type
                    ty = dyn_cast<PointerType>(ty)->getElementType();

                    foundArray = true;

                } else if (ty->isArrayTy()) {       // array type
                    ty = dyn_cast<ArrayType>(ty)->getElementType();
                    
                    foundArray = true;

                } else if (ty->isStructTy()) {      // struct type
                    
                    /* get offset within the struct */
                    if (const ConstantInt *ci = dyn_cast<ConstantInt>(ii)) {
                        unsigned index = ci->getLimitedValue();

                        /* iterate over (sub)element of the struct to find the right index */
                        for (auto jj=elt->subElements.begin(); jj!=elt->subElements.end(); ++jj) {
                            if ((*jj)->idx == index) {
                                elt = *jj;          // index found
                                break;              // stop searching
                            }
                        }         

                        /* dig into the next type of GEP */
                        ty = dyn_cast<StructType>(ty)->getElementType(index);
                    }

                } else {
                    warning() << "Unknown GEP type: " << *ii << "Skip.\n";

                    return nullptr;                 // failure
                }
            }
        }

        // TODO: Shall we check LoadInst and StoreInst?
    }

    /* return the same element or NULL based on 'skipArray' flag */
    if (!skipArray && foundArray && elt == arg) {
       return nullptr;
    }

    return elt;
}



// ------------------------------------------------------------------------------------------------
// Check whether a Value represents a constant, and if so, create the appropriate templated
// Attribute and downcast it to BaseAttr, to enable polymorphism.
//
interwork::BaseAttr *Backward::extractConst(const Value *val, interwork::Argument *iwArg) {

    /* check if value is a constant at all */
    if (!dyn_cast<Constant>(val)) {       
        iwArg->baseType = interwork::Ty_i8;         // make sure that this is not Ty_invalid

        return (new interwork::Attributes<uint8_t>(ATTR_DEAD, "uint8_t"));
    }
                          
    

    // --------------------------------------------------------------------- //
    //                * Extract the actual constant value  *                 //
    // --------------------------------------------------------------------- //
    if (dyn_cast<ConstantPointerNull>(val)) {       // NULL pointer?
        iwArg->baseType = interwork::Ty_i8;

        return (new interwork::Attributes<uint8_t>(ATTR_NULLPTR, "uint8_t"));
    }
    
    // ----------------------------------------------------------------------------------
    else if (const ConstantInt *ci = dyn_cast<ConstantInt>(val)) {

        // /* make sure that the value and the type size are compatible */
        // if ((iwArg->baseType == interwork::Ty_i8  && ci->getBitWidth() != 8)  || 
        //     (iwArg->baseType == interwork::Ty_i16 && ci->getBitWidth() != 16) ||
        //     (iwArg->baseType == interwork::Ty_i32 && ci->getBitWidth() != 32) ||
        //     (iwArg->baseType == interwork::Ty_i64 && ci->getBitWidth() != 64)) {
        // 
        //         throw FuzzGenException("extractConst(): Incompatible type size!");
        // }

        // baseTy is verified here. The int64_t doesn't really matters here.
        interwork::Attributes<int64_t> *attr = 
                new interwork::Attributes<int64_t>(ATTR_PREDEFINED, "int64_t");
          
       
        attr->push(ci->getSExtValue());             // store constant value

        return attr;
    }

    // ----------------------------------------------------------------------------------
    else if (const ConstantFP *fp = dyn_cast<ConstantFP>(val)) {
        // (TODO: make sure that baseTy is correct, as I did above)
        iwArg->baseType = interwork::Ty_double;              // use largest type

        interwork::Attributes<double> *attr = 
                new interwork::Attributes<double>(ATTR_PREDEFINED, "double");

        attr->push(fp->getValueAPF().convertToDouble());

        return attr;
    }

    // ----------------------------------------------------------------------------------
    // use stripPointerCasts(), as casting to void* is common for functions pointers
    // 
    // NOTE: This check must be before GlobalValue as functions are also globals
    else if (const Function *func = dyn_cast<Function>(val->stripPointerCasts())) {
        iwArg->baseType = interwork::Ty_funcptr;

        interwork::Attributes<int> *attr = 
                new interwork::Attributes<int>(ATTR_FUNCPTR, "");

        attr->addRef(func->getName());

        return attr;
    }

    // ----------------------------------------------------------------------------------
    // Global variable
    else if (const GlobalValue *glo = dyn_cast<GlobalValue>(val)) {

        fatal() << "Come back to that! " << *glo << "\n";
        
   
        interwork::Attributes<int64_t> *attr = 
                new interwork::Attributes<int64_t>(ATTR_PREDEFINED, "int64_t");

       
        attr->push(0);             // store constant value
        return attr;
    }

    // ----------------------------------------------------------------------------------
    // look for constant arrays. The idea here is to get all the distinct values from
    // the array and use them as predefined values to initialize it at runtime.
    else if (const ConstantExpr *cexp = dyn_cast<ConstantExpr>(val)) {

        /* make sure that cexp is getlementptr with static indices */
        if (!cexp->isGEPWithNoNotionalOverIndexing()) {
            //throw FuzzGenException("extractConst(): Non-static array");

            return (new interwork::Attributes<uint8_t>(ATTR_FAILURE, "uint8_t"));
        }


        /* global static arrays */
        if (const GlobalVariable *glo = dyn_cast<GlobalVariable>(cexp->stripPointerCasts()) ) {

            if (const ConstantAggregateZero *agg = 
                    dyn_cast<ConstantAggregateZero>(glo->getInitializer())) {

                interwork::Attributes<int64_t> *attr = 
                        new interwork::Attributes<int64_t>(ATTR_PREDEFINED, "int64_t");

                /* get array size */
                iwArg->nsz = agg->getNumElements();
                iwArg->sz.push_back(agg->getNumElements());
              
                /* assume that type size is ok */
                if (const ConstantInt *ci = dyn_cast<ConstantInt>(agg->getElementValue((unsigned)0))) {
                    attr->push(ci->getSExtValue());
                }

                else {
                    throw FuzzGenException("extractConst(): Aggregate with non constant values");

                }
                return attr;
            }

            /* local data arrays */
            else if (const ConstantDataArray *arr = 
                        dyn_cast<ConstantDataArray>(glo->getInitializer())) {

                interwork::Attributes<int64_t> *attr = 
                        new interwork::Attributes<int64_t>(ATTR_PREDEFINED, "int64_t");

                /* get array size */
                iwArg->nsz = arr->getNumElements();
                iwArg->sz.push_back(arr->getNumElements());
              
                /* assume that type size is ok */
              
                /* get all array elements are predefined values */         
                for (unsigned i=0; i<arr->getNumElements(); ++i) {
                    if (const ConstantInt *ci = 
                            dyn_cast<ConstantInt>(arr->getElementAsConstant(i))) {

                        attr->push(ci->getSExtValue());
                    }
                }

                return attr;
            }
        }


        warning() << "Constant expression analysis may failed. Please check this.\n";

        /* not a static array. Just return a dead argument */
        return new interwork::Attributes<uint8_t>(ATTR_NULLPTR, "uint8_t");
    }

    // ----------------------------------------------------------------------------------
    else {
        // unknown constant.
        fatal() << "Value is an unknown constant: " << *val << "\n";
        fatal() << "Value is has type: " << *val->getType() << "\n";

        throw FuzzGenException("extractConst(): Unknown type of Constant");

        // return new interwork::Attributes<uint8_t>(ATTR_NULLPTR, "uint8_t");
    }  
}



// ------------------------------------------------------------------------------------------------
// Analyze a function pointer to check whether it corresponds to a function wrapper. A wrapper
// has the following form:
//
//      type wrapper(type arg1, type arg2, ..., type argN) {
//          return stdcall(arg2, argN, ... arg1);
//      }
//
// Anything else is not supported.
//
bool Backward::analyzeWrapper(const Function *F, interwork::FunctionPtr* &funcPtr) {
    const CallInst *callee = nullptr;
    unsigned       N       = 0;


    info(v1) << "Analyzing function pointer '" << F->getName() << "'\n";

    /* make sure that funcPtr is properly initialized */
    if (funcPtr == nullptr) {
        funcPtr         = new interwork::FunctionPtr();
        funcPtr->retval = new interwork::Argument();
    }

    /* iterate over every instruction */
    for (const Instruction &inst : instructions(F)) {

        /* look for call instructions */
        if (const CallInst *call = dyn_cast<CallInst>(&inst)) {
            if (call->getCalledFunction() == nullptr) {
                warning() << "Cannot get called function!\n";
                continue;                           // we can't get name
            }

            funcPtr->callee = call->getCalledFunction()->getName();

            if (Root::inBlacklist(funcPtr->callee)) {
                continue;                           // skip blacklisted functions
            }

            callee = call;                          // save call instruction (needed for return)


            info(v1) << "Call to function '" << funcPtr->callee << "' found.\n";           

            /* function wrappers have only one callee. If not, halt analysis */
            if (++N > 1) {
                funcPtr->callee = "";
                return false;
            }


            /* for every argument of the callee, find which argument uses from the wrapper (F) */
            for (unsigned i=0; i<call->getNumOperands(); ++i) {                
                deque<const Instruction *> D;

                if(const Value *val = dyn_cast<Value>(call->getOperand(i))) {
                    int status;

                    /* find argument's alloca, and its stores */
                    if(const AllocaInst *alloca = findAlloca(val, D, status)) {

                        list<StoreOp *> stores = findStores(alloca, call);

                        for (auto ii=stores.begin(); ii!=stores.end(); ++ii) {
                            unsigned j = 0;


                            if ((*ii)->type == SO_TYPE_STORE) {
                                /* check if the store's value corresponds to an F's argument */ 
                                for (auto &jj : F->args()) {
                                    if (&jj == (*ii)->store->getValueOperand()) {
                                        info(v1) << "Argument mapping: " << i << " -> " << j << "\n";

                                        /* save mapping */
                                        funcPtr->paramMap.push_back(j);
                                    }

                                    ++j;
                                }
                            }
                        }
                    }
                }
            }
        }

        /* also check the return value */
        else if (const ReturnInst *retn = dyn_cast<ReturnInst>(&inst)) {
            info(v1) << "Return Value found:" << *retn << "\n";

            /* make sure that there's a single return */
            if (++N > 2) {
                funcPtr->callee = "";
                return false;
            }

            /* check whether function's return value User is return (unique due to SSA) */
            funcPtr->retValUsed = (retn->getReturnValue() == callee);
        }
    }

    return true;                                    // analysis was successful
}



// ------------------------------------------------------------------------------------------------
// Find the argument's prefix (*, &, or none). Argument's type does not always match with the
// alloca's type.
//
int Backward::findPrefix(deque<const Instruction *> D) {
    
    /* follow the user chain */
    while (!D.empty()) {
        const Instruction *inst = D.back();
        D.pop_back();

        if (dyn_cast<LoadInst>(inst)) {
            return interwork::Pref_deref;           // if you hit a load, it's a dereference
        }        


        // TODO: This function is incomplete, but it works so far
    }

    return interwork::Pref_none;
}



// ------------------------------------------------------------------------------------------------
// Merge the argument's attributes into a single. Internal analysis proposed a set of attributes,
// while External analysis proposed another one (potentially different). This function combines
// these attributes into a single.
//
interwork::BaseAttr *Backward::mergeAttributes(interwork::BaseAttr *intAttr,  
        interwork::BaseAttr *extAttr) {

/* MACRO to get the Least Significant Bit */
#define LSB(x) ((x) & 0xff)

    int intA = intAttr->flags,                      // internal attributes
        extA = extAttr->flags;                      // external attributes

    /*
        Attributes (copied from common.h):

        ATTR_FAILURE    = 0xffff,                   // analysis failed (MSBit is set)
        ATTR_DEAD       = 0x0000,                   // arg is not used
        ATTR_INVARIANT  = 0x0001,                   // arg is not modified
        ATTR_PREDEFINED = 0x0003,                   // arg takes a constant value from a set
        ATTR_RANDOM     = 0x00ff,                   // arg is neither invariant nor predefined
        ATTR_ARRAY      = 0x0100,                   // arg is used as an array (pointers ONLY)
        ATTR_ARRAYSIZE  = 0x0200,                   // arg represents buffer size
        ATTR_WRITEONLY  = 0x0400,                   // arg is used to hold output (pointers ONLY)
        ATTR_BYVAL      = 0x0800,                   // arg is passed by value
        ATTR_NULLPTR    = 0x1000,                   // arg is NULL (pointers ONLY)
        ATTR_DEPENDENT  = 0x2000,                   // arg depends on another argument
        ATTR_REFERENCE  = 0x4000,                   // arg is a reference of another variable
        ATTR_FUNCPTR    = 0x8000                    // arg is a function pointer
    */


    /* 
     * TODO: Consider all cases. For now we use only the ones that we need. Add more as you go
     */
    

    if (intA == ATTR_FAILURE || extA == ATTR_FAILURE) {
        throw FuzzGenException("mergeAttributes(): Failure attribute");
    }

    /* if external argument is not set, but internal is random, don't use this argument */
    else if (LSB(intA) == ATTR_RANDOM && extA == ATTR_DEAD) {
        return extAttr;
    }

    else if (intA == ATTR_DEAD) {
        return extAttr;
    }

    else if (extA == ATTR_DEAD) {
        return intAttr;
    }

    else if (LSB(intA) == ATTR_RANDOM && LSB(extA) == ATTR_RANDOM) {
        intAttr->flags |= extAttr->flags;           // merge other flags
        return intAttr;
    }

    else if (LSB(intA) == ATTR_RANDOM && LSB(extA) == ATTR_PREDEFINED) {
        extAttr->flags |= intAttr->flags & 0xff00;  // merge other flags (ignore LSB)
        return extAttr;
    }

    else if (LSB(intA) == ATTR_INVARIANT && (extA & ATTR_NULLPTR)) {
        return extAttr;
    }

    else if (LSB(intA) == ATTR_INVARIANT && LSB(extA) == ATTR_PREDEFINED) {
        extAttr->flags |= intAttr->flags;           // merge other flags
        return extAttr;
    }
    
    else if (LSB(intA) == ATTR_INVARIANT && LSB(extA) == ATTR_RANDOM) {
        extAttr->flags |= intAttr->flags;           // merge other flags
        return extAttr;
    }

    else if (LSB(intA) == ATTR_INVARIANT && (extA & ATTR_FUNCPTR)) {
        return extAttr;
    }

    else if (LSB(intA) == ATTR_PREDEFINED && LSB(extA) == ATTR_DEAD) {
        intAttr->flags |= extAttr->flags;           // merge other flags
  
        return intAttr;
    }

    else if (LSB(intA) == ATTR_PREDEFINED && LSB(extA) == ATTR_INVARIANT) {
        intAttr->flags |= extAttr->flags;           // merge other flags

        // WARNING: After this merging, the same value may appear >1 (not a set anymore).

        return intAttr;
    }

    else if (LSB(intA) == ATTR_PREDEFINED && LSB(extA) == ATTR_PREDEFINED) {
        intAttr->flags |= extAttr->flags;           // merge other flags

        // WARNING: After this merging, the same value may appear >1 (not a set anymore).

        /* merge predefined values */        
        for (auto ii=extAttr->predefinedVals.begin(); ii!=extAttr->predefinedVals.end(); ++ii) {
            intAttr->predefinedVals.insert(*ii);
        }


        return intAttr;
    }

    else if (LSB(intA) == ATTR_PREDEFINED && LSB(extA) == ATTR_RANDOM) {
        extAttr->flags |= intAttr->flags;           // merge other flags
  
        return extAttr;
    }

    else if ((intA & ATTR_FUNCPTR) && (extA & ATTR_FUNCPTR)) {
        return extAttr;                             // external analysis dominates
    }

    else if ((intA & ATTR_FUNCPTR) && (extA & ATTR_NULLPTR)) {
        return extAttr;                             // a NULL is passed as a function pointer
    }

    else if ((intA & ATTR_FUNCPTR) && LSB(extA) == ATTR_PREDEFINED) {
        return intAttr;                             // function pointer dominates
    }

    else if (LSB(intA) == ATTR_INVARIANT && (extA & ATTR_ARRAY)) {
        intAttr->flags |= ATTR_ARRAY;
        return intAttr;
    }

    else if ((intA & ATTR_ARRAYSIZE) && LSB(extA) == ATTR_PREDEFINED) {
        return extAttr;
    }
    
    else if ((intA & ATTR_ARRAY) && LSB(extA) == ATTR_PREDEFINED) {
        return intAttr;
    }

    else if ((intA & ATTR_ARRAY) && LSB(extA) == ATTR_RANDOM) {
        return intAttr;
    }

    else if ((extA & ATTR_ARRAY) && LSB(intA) == ATTR_RANDOM) {
        return extAttr;
    }

    else if (LSB(intA) == ATTR_RANDOM && (extA & ATTR_NULLPTR)) {
        return extAttr;
    }

    else if (LSB(intA) == ATTR_RANDOM && (extA & ATTR_FUNCPTR)) {
        return extAttr;
    }

    else if ((intA & ATTR_WRITEONLY) && (extA & ATTR_PREDEFINED)) {
        return extAttr;
    }

    else if ((intA & ATTR_NULLPTR) && (extA & ATTR_PREDEFINED)) {
        return extAttr;
    }

    else if ((intA & ATTR_WRITEONLY) && (extA & ATTR_NULLPTR)) {
        return extAttr;
    }

    else if (intA == extA) {                        // it doesn't matter if attributes are the same
        return intAttr;
    }

    else {
        ostringstream oss;

        oss << "Internal Attributes: 0x" << hex << intA << "\n\t"
            << "External Attributes: 0x" << hex << extA << "\n";

        fatal() << oss.str() << "\n";

        fatal() << "Please add the case in mergeAttributes()." << "\n";

        throw FuzzGenException("mergeAttributes(): Unknown case!");
    }
  

    return nullptr;

#undef LSB
}



// ------------------------------------------------------------------------------------------------
// Adjust a type (i.e., the interwork objects) if casting is used.
//
bool Backward::adjustType(llvm::Argument *arg, Type *allocaTy, interwork::Argument* &iwArg,
         deque<const Instruction *> &D, int depth) {


    /* ------------------------------------------------------------------------
     * If casting is used (i.e., types are different), dig into the argument
     * (of the new type) to prepare the interwork objects accordingly.
     * ------------------------------------------------------------------------ */
    if (!iwArg->compare(Dig::getTypeStr(allocaTy), true)) {
        interwork::Argument *iwArg2 = iwArg;
        StringRef           funName = arg->getParent()->getName();
        Type                *type   = allocaTy;
        

        /* If a Type object has already been analyzed, don't "dig" again, but return 
         * the same object instead. This is required in cases that we have a dependence
         * and we need to make changes to an already analyzed Argument (i.e., extIWElt).
         *
         * However, we don't want to return the same object for Types that belong to
         * different "base" arguments/APICall objects (a "base" argument is passed
         * directly to the API call) because these objects are independent.
         *
         * To distinguish between these 2 cases we leverage the depth of backward slicing:
         * When depth == 0, adjustType() needs to find the type of a "base" argument,
         * thus a new object is required. When depth > 0, adjustType(), looks up for a
         * previous instance of the object (that was analyzed as some previous slice),
         * so that object needs to be returned.
         *
         * The above method works because the objects to "base" arguments are independent
         * to each other (argument dependencies are marked with depIDs), but actual objects
         * remain independent.
         */
        if (depth && prevIW.find(type) != prevIW.end()) {
            iwArg = prevIW[allocaTy];
            return true;
        }


        info(v1) << "Casting was used: " << iwArg->tyStr << " -> " << *type << "\n";

        /* run dig and magic modules (again) on the new argument type */
        DigWrapper *DG = new DigWrapper(iwArg, funName, arg->getArgNo(), type, true, ctx);      

        DG->runOnModule(libModule);


        if (iwArg == nullptr) {
            // Dig on internal module failed.
            //
            // The most common cause is the failure to find the struct type definition in the
            // internal module, even though that definition exists in the external module.
            // For example, consider the following code from libhevc:
            //
            //      WORD32 ihevcd_set_num_cores(iv_obj_t *ps_codec_obj, void *pv_api_ip,
            //                                  void *pv_api_op) {
            //
            //          ihevcd_cxa_ctl_set_num_cores_op_t *ps_op;
            //          ps_op = (ihevcd_cxa_ctl_set_num_cores_op_t *)pv_api_op;
            //          ps_op->u4_error_code = 0;
            //      }
            //      
            // The equivalent IR is the following:
            //
            //      define i32 @ihevcd_set_num_cores(%struct.iv_obj_t*, i8*, i8*) {
            //        %6 = alloca i8*, align 8
            //        %8 = alloca %struct.fmt_conv_t*, align 8
            //        store i8* %2, i8** %6, align 8
            //      
            //        %16 = load i8*, i8** %6, align 8
            //        %17 = bitcast i8* %16 to %struct.fmt_conv_t*
            //        store %struct.fmt_conv_t* %17, %struct.fmt_conv_t** %8, align 8
            //      
            //        %23 = load %struct.fmt_conv_t*, %struct.fmt_conv_t** %8, align 8
            //        %24 = getelementptr inbounds %struct.fmt_conv_t, 
            //                                     %struct.fmt_conv_t* %23, i32 0, i32 
            //        store i32 0, i32* %24, align 4
            //      }
            //
            // As you can see here, there's no definition of ihevcd_cxa_ctl_set_num_cores_op_t,
            // but for some reason, fmt_conv_t is used instead.
            //
            // To solve this inconsistency, we look for the definition in external module (which
            // we know that exists) and we rely exclusively on external analysis.


            /* If we already have the interwork object(s) for this type, use it*/            
            if (origIW.find(allocaTy) != origIW.end()) {
                // This is important when we have dependencies 
                // and we need to set attributes to both sides.
                iwArg = origIW[ allocaTy ];
                iwArg = iwArg->deepCopy();

                emph(v2) << "Reusing Argument: " << iwArg->dump() << "\n";
            } else {
                Dig *dig = new Dig(module, ctx);

                /* build interwork object (there's no need to use magic) */
                if (!(iwArg = dig->digType(*arg, allocaTy, false))) {
                    return false;
                }

                origIW[ allocaTy ] = iwArg;

                baseIwArg[Dig::getBaseTypeStr(allocaTy)] = iwArg;
            }

            info(v1) << "Using argument from external module: " << iwArg->dump() << "\n";
        }

        delete iwArg2;                              // we don't need the old one anymore

        // DigWrapper set tyStr with the type from the library module, which doesn't contain
        // any pointers, so it may not reflect the actual argument's type. So we set it again.
        iwArg->tyStr  = Dig::getTypeStr(allocaTy);


        /* if we have a pointer, prefix makes sense */
        if (iwArg->nptrs() > 0) {
            iwArg->prefix = findPrefix(D);          // find argument's prefix
        }

        /* store root argument */
        if (!depth) {
            prevIW[type] = iwArg;
        }

    } else {
        info(v2) << "Argument used without casting.\n";

        /* no need to take any action */
    }

    return true;
}



// ------------------------------------------------------------------------------------------------
// Static backward slicing.
//
int Backward::backwardSlicing(llvm::Argument *arg, const Value *val, interwork::Argument* &iwArg,
        const Instruction *entry, deque<const Instruction *> *valChain, bool typeOnly, int depth) {

    int rval;                                       // hold return value from recursions


    info(v0) << "Starting a backward slice (" << depth << ") from:" << *entry << "\n";

    // if (depth > 1) {
    //     throw FuzzGenException("backwardSlicing(): Debug this case");
    // }

    // --------------------------------------------------------------------- //
    //                      * Prevent infinity loops *                       //
    // --------------------------------------------------------------------- //
    if (!depth) {
        visitedValues.clear();                      // zero this out for zero depth  
    }

    if (visitedValues.find(val) != visitedValues.end()) {
        info(v2) << "Value '" << *val << "' is already visited. Abort.\n";

        return BWSLICE_RETVAL_ERROR;                 // don't re-analyze values
    }

    visitedValues[val] = true;                      // mark value as analyzed


    // --------------------------------------------------------------------- //
    //                 * Find alloca for the current value *                 //
    // --------------------------------------------------------------------- //
    deque<const Instruction *> D;                   // data flow through alloca
    deque<const Instruction *> D_bkp;               // backup data flow (we need it at the end)
    int                        status;    
    const AllocaInst           *alloca = findAlloca(val, D, status);


    if (!alloca && status == ST_ERROR_CONST_VALUE) {
        /* if argument does not have any type, adjust it first */
        if (iwArg->tyStr == "$NOTYPE$") {
            if (!adjustType(arg, val->getType(), iwArg, D, depth)) {
                iwArg = nullptr;

                fatal() << "Cannot adjust type.\n";
                
                return BWSLICE_RETVAL_ERROR;
            }
        }

        /* Value is a constant (no alloca exists) */
        iwArg->attr = extractConst(val, iwArg);

        return BWSLICE_RETVAL_SUCCESS;              // slicing succeeded!

    } if (!alloca && status == ST_ERROR_CALL_FOUND) {
        
        /*  analysis failed. Give it a random attribute */
        iwArg->attr = new interwork::Attributes<uint8_t>(ATTR_RANDOM, "uint8_t");

        return BWSLICE_RETVAL_SUCCESS;              // slicing succeeded!

    }else if (!alloca) {
        fatal() << "Alloca cannot be found. Error code: " << status << "\n";

        return BWSLICE_RETVAL_ERROR;                // different failure. Abort    
    }


    /* display and verify the dataflow chain */
    info(v2) << "DataFlow chain:\n";

    for (auto ii=D.rbegin(); ii!=D.rend(); ++ii) {
        info(v2) << "\t" << **ii << "\n";
 

        /* instructions whitelist (make sure is consistent with dependence.cpp:findAlloca()) */
        if (!dyn_cast<AllocaInst>       (*ii) &&
            !dyn_cast<GetElementPtrInst>(*ii) &&
            !dyn_cast<BitCastInst>      (*ii) &&
            !dyn_cast<ZExtInst>         (*ii) &&
            !dyn_cast<SExtInst>         (*ii) &&
            !dyn_cast<ICmpInst>         (*ii) &&
            !dyn_cast<LoadInst>         (*ii) &&
            !dyn_cast<TruncInst>        (*ii)) {
            
            
                fatal() << "Instruction '" << **ii << "' is invalid. Flagging argument as random.\n";

                //iwArg->attr = new interwork::Attributes<uint8_t>(ATTR_DEAD, "uint8_t");
                iwArg->attr = new interwork::Attributes<uint8_t>(ATTR_RANDOM, "uint8_t");

                if (valChain) {
                    valChain->clear();              // clear chain if exists
                }

                /* at 0 depth, just return assuming success :) */
                if (!depth) {
                    return BWSLICE_RETVAL_SUCCESS;
                }

                return BWSLICE_RETVAL_ERROR;
        }

        /* take a backup of the original data flow chain (needed for final adjustments) */
        if (!depth) {
            D_bkp.push_back(*ii);
        }
    }


    /* adjust argument's type in case of casting */
    if (!adjustType(arg, alloca->getType(), iwArg, D, depth)) {
        iwArg = nullptr;

        fatal() << "Cannot adjust type.\n";

        return BWSLICE_RETVAL_ERROR;
    }


    /*
     * At this point, internal and external analyses are consistent. Hence, merging
     * their results (i.e., attributes) into a single interwork object is trivial.
     */
    iwArg->setByExt = true;


    // --------------------------------------------------------------------- //
    //                        * Miscellaneous tasks *                        //
    // --------------------------------------------------------------------- //
    // If we already have the interwork object(s) for this type, use it. This
    // is important when we have dependencies and we need to set attributes
    // to both sides. We do this only for structs as we have various castings
    // from (void*).
    //
    if (alloca->getType()->isStructTy()) {

        if (typeToIW.find(alloca->getType()) != typeToIW.end()) {
            delete iwArg;

            iwArg = typeToIW[ alloca->getType() ];

            info(v2) << "Reusing Argument: " << iwArg->dump() << "\n";
        } else {
            typeToIW[ alloca->getType() ] = iwArg;  // store object
        }
    }

    // /* if we're interested only in building the interwork objects, we can stop here */
    // if (typeOnly) return BWSLICE_RETVAL_SUCCESS;


    /* map alloca with the interwork object (only for depth == 0, i.e., initial arguments) */
    if (!depth) {
        if (allocaMap.find(alloca) == allocaMap.end()) {
            allocaMap[alloca] = iwArg;
        }
    }


    // --------------------------------------------------------------------- //
    //             * Find all store instructions in this slice *             //
    // --------------------------------------------------------------------- //
    list<StoreOp *> stores = findStores(alloca, entry);

    if (stores.size() < 1) {
        fatal() << "No stores found for current value. Abort slicing...\n";

        // update: Element may be write_only, so we still need to have the right type 
        // return BWSLICE_RETVAL_FAILED;

        iwArg->attr->flags |= ATTR_WRITEONLY;
    }

 
    for (auto ii=stores.begin(); ii!=stores.end(); ++ii) {

        /* special case (we hit a function call) */
        if ((*ii)->type == SO_TYPE_CALL) {
            info(v2) << "Analyzing store through '" << ((*ii)->call.funame) << "' call\n";

            if (iwArg->isBasicStripped()) {         // make sure that argument is of basic type

                /* Function treats argument as an array and stores values from an external 
                 * source to it. All functions in byRefCalls deal with pointers to buffers,
                 * so we know that we have an array that needs to be fuzzed.
                 */
                iwArg->attr->flags |= ATTR_RANDOM;

                /* if argument is already a constant array, don't give the array attribute again */
                if (iwArg->nsz == 1) {
                    iwArg->attr->flags |= ATTR_ARRAY;
                    iwArg->attr->flags &= ~ATTR_NULLPTR;
                }

            } else {
                /* this should never happen */
                // TODO: Are you sure? :|
                //throw FuzzGenException("backwardSlicing(): Call by reference to non basic argument");                
            }
            
            continue;
        }


        /* get pointer and value of the store */
        const Value *pointer = (*ii)->store->getPointerOperand(),
                    *value   = (*ii)->store->getValueOperand();

        info(v2) << "Analyzing store:" << *((*ii)->store) << "\n";


        // TODO: What if we have multiple stores on the same variable? 
        //       Shall we do a REACH-DEF analysis to see which is last?


        // --------------------------------------------------------------------- //
        //           * Compare DataFlows (for recursive calls only) *            //
        // --------------------------------------------------------------------- //
        if (valChain != nullptr) {
            /* build the dataflow chain from pointer to alloca */
            deque<const Instruction *> ptrChain;
            int                        status;


            /* find the dataflow chain */
            findAlloca(pointer, ptrChain, status);

            /* check whether the 2 dataflows access the same element */
            if (findIWElement(*valChain, iwArg) != findIWElement(ptrChain, iwArg)) {
                info(v2) << "Dataflows access different elements. Discarding store...\n";
                
                continue;                           // discard the store
            }
        }

        /* find the appropriate sub-element using the alloca chain in D */
        findAlloca(pointer, D, status);
        interwork::Argument *iwElt = findIWElement(D, iwArg);

        iwElt->setByExt = true;                     // external module uses this element


        /* if field name is a "size" variable give it the right attribute */
        if (iwElt->fieldName.find("size") != string::npos) {

            // NOTE: attr may already have other values as well (e.g., predefined). In that
            //       case the array size is weaker than the other values. That is, composer
            //       ignores the array size when other attributes are set.
            iwElt->attr->flags |= ATTR_ARRAYSIZE;

            // continue analysis as size variable may get a predefined value 
            // (!= DEFAULT_ARRAY_SIZE)
        }


        // --------------------------------------------------------------------- //
        //                          * Constant Value *                           //
        // --------------------------------------------------------------------- //
        if (dyn_cast<Constant>(value)) {   
            interwork::BaseAttr *B = extractConst(value, iwElt);

            /* if attr corresponds to function pointer, update function name in declaration */
            if (B->flags & ATTR_FUNCPTR) {

                /* analyze function (assuming it's a wrapper) */
                const Function *funcptr = dyn_cast<Function>(value->stripPointerCasts());
                
                /* check if function pointer is part of the API */
                if (libAPI.find(funcptr->getName()) != libAPI.end()) {
                    info(v1) << "Function pointer '" << funcptr->getName()
                             << "' is part of the API.\n";

                    if (!iwElt->funcptr) {          // make sure that it's initialized
                        iwElt->funcptr          = new interwork::FunctionPtr();
                        iwElt->funcptr->retval  = new interwork::Argument();
                        iwElt->funcptr->hasDecl = false;
                    }
                } else {
                    if (analyzeWrapper(funcptr, iwElt->funcptr)) {
                        iwElt->funcptr->hasDecl = true;
                        iwElt->funcptr->funame  = B->getRef();
                    } else {
                        throw FuzzGenException("backwardSlicing(): Wrapper analysis failed");
                    }
                }
            }

            /* merge internal and external attributes */            
            iwElt->attr = mergeAttributes(iwElt->attr, B);

            emph(v3) << "Interwork Element stage 1: " << iwElt->dump() << "\n";
        }


        // --------------------------------------------------------------------- //
        //                  * Non Constant Value (recursion)  *                  //
        // --------------------------------------------------------------------- //
        else {
            /*
             * When we have things like value = a + b, or value++, we give the
             * random attribute to the value as it's very hard to predict the
             * actual value.
             * 
             * Also in cases such as value++, backward slicing ends up following
             * the same 'store' again and again, resulting in infinity loops.
             * However, visitedValues prevents this case.
             *
             * TODO: Detect a+b etc. (use the same approach from magic)
             */


            /* build the dataflow chain from value to alloca */
            deque<const Instruction *> valChain;
            int                        status;
            const AllocaInst           *newAlloca = findAlloca(value, valChain, status);


            if (newAlloca == nullptr) {
                if (status == ST_ERROR_CALL_FOUND) {

                    /* check if function is in the list */
                    for (auto ii=byRefCalls.begin(); ii!=byRefCalls.end(); ++ii) {
                        if (calledFunc.find((*ii).first) != string::npos) {

                            /* return value in called functions. It's the buffer size */         
                            iwElt->attr->flags |= ATTR_ARRAYSIZE;
                            break;
                        }
                    }


                    /* if we came from an memory allocation then we have an array ;) */
                    for (auto ii=allocFam.begin(); ii!=allocFam.end(); ++ii) {
                        if (calledFunc == *ii) {
                            emph(v2) << "Array found through '" << calledFunc << "' !\n";

                            /* when we malloc basic types it's an array */
                            /* when we malloc structs, it's probably a dynamic object */
                            if (iwElt->isBasicStripped()) {
                                iwElt->attr->flags |= ATTR_ARRAY;
                            } else {
                                info(v2) << "(not an array, but a struct actually)\n";
                            }
                        }
                    }

                } else {
                   
                    // TODO: This is very naive. Find a better way to do it.
                    if (value->getName() == "data") {
                        iwElt->attr->flags |= ATTR_ARRAY;
                    
                    } else if (value->getName() == "size") {
                        iwElt->attr->flags |= ATTR_ARRAYSIZE;
                    
                    } else {
                        fatal() << "Cannot find Value's alloca. Skip current store.\n";
                    }
                }
                
                continue;                
            }
         
            /* if alloca is the same (this happens when variable modifies itself e.g., i++) */
            else if (newAlloca == alloca) {
                info(v0) << "Store is self-modifying. Skip current store.\n";
                continue;
            }


            /* first, prepare the interwork objects for value's type */
            Dig *dig = new Dig(module, ctx);
                
            /* prepare interwork objects for the new type (there's no need to use magic) */
            interwork::Argument *valArg = dig->digType(*arg, value->getType(), false);


            /* check if we have a dependency */
            if (allocaMap.find(newAlloca) != allocaMap.end()) {

                // /* use the backward slicing, just to find the right interwork argument */
                // info(v2) << "-------------------------------------------------- (1)\n";
                //
                // backwardSlicing(arg, value, valArg, (*ii)->store, &valChain, true, depth+1);
                //
                // info(v2) << "-------------------------------------------------- (1)\n";


                /* find the appropriate element using the dataflow chain from "value" */
                if (interwork::Argument *extIWElt = 
                        findIWElement(valChain, allocaMap[newAlloca], false)) {

                    extIWElt->setByExt = true;

                    /* The dependent argument defines the dependency */
                    // use dID+offset to distinguish dependencies from different struct elements
                    extIWElt->depTy = interwork::Dep_def;
                    extIWElt->depID = (dID[newAlloca] << 16) | extIWElt->off;

                    /* The current argument, gets initialized from it */
                    iwElt->depTy     = interwork::Dep_init;
                    iwElt->depIDInit = (dID[newAlloca] << 16) | extIWElt->off;

                    emph(v2) << "Dependency Found: " << extIWElt->dump() << "\n";                
                    emph(v2) << "Dependency Found: " << iwElt->dump()    << "\n";
                }

            } else {
                /* recursively, continue the backward slicing */
                // valChain.clear();
                info(v2) << "-------------------------------------------------- (2)\n";

                rval = backwardSlicing(arg, value, valArg, (*ii)->store, &valChain, false, depth+1);

                info(v2) << "-------------------------------------------------- (2)\n";
                

                /* check if backward slicing failed */
                if (rval != BWSLICE_RETVAL_SUCCESS) {
                    info(v2) << "Backward Slicing was not successful. Ignore results.\n";

                    continue;   
                }


                /* find the appropriate element using the dataflow chain from "value" */
                if (interwork::Argument *extIWElt = findIWElement(valChain, valArg)) {

                    emph(v2) << "Interwork Element stage 2: " << iwElt->dump() << "\n";
                    emph(v2) << "Interwork Element stage 3: " << extIWElt->dump() << "\n";


                    /* do we have a type mismatch? */
                    if (iwElt->tyStr != extIWElt->tyStr) {
                        // Type mismatch. This probably means that we have an alias:
                        //
                        //      ihevcd_cxa_ctl_degrade_ip_t s_ctl_ip;
                        //      void *pv_api_ip;
                        //
                        //      pv_api_ip = (void *)&s_ctl_ip;
                        //
                        //      api_foo(.., pv_api_ip, ...);
                        //
                        // In that case, we analyze the alias again, but this time we follow all 
                        // dataflows (valChain == NULL) and we use the external element instead

                        /* repeat the backward slicing, but this time access all dataflows */
                        info(v2) << "-------------------------------------------------- (3)\n";

                        // value is already visited (from previous call) so we have to clear it
                        visitedValues.erase(value);

                        rval = backwardSlicing(arg, value, valArg, (*ii)->store, nullptr, false, 
                                               depth+1);

                        info(v2) << "-------------------------------------------------- (3)\n";


                        /* check if backward slicing failed */
                        if (rval != BWSLICE_RETVAL_SUCCESS) {
                            info(v2) << "Backward Slicing was not successful. Ignore results.\n";

                            continue;   
                        }


                        /* important! Update extIWElt, after the recursion */
                        extIWElt = findIWElement(valChain, valArg, true);

                        if (!iwElt->parent) {
                            info(v2) << "Replacing argument ...\n";

                            /* for original arguments (no parent), we replace it */
                            iwElt->replace(extIWElt);

                        } else {
                            /* elements, cannot be replaced, as they're inside a struct */
                            info(v2) << "Replacing element ...\n";

                            /* check type (case arrays vs elt) */
                            if (iwElt->nptr[0] != extIWElt->nptr[0]) {
                                // this happens when extIWElt is an array but it's indexed

                                // TODO: What to do?
                            }

                            /* so, first save all struct-related fields */
                            uint8_t  idx        = iwElt->idx;
                            string   tyStr      = iwElt->tyStr,
                                     name       = iwElt->name,
                                     structName = iwElt->structName,
                                     fieldName  = iwElt->fieldName;
                            uint64_t off        = iwElt->off;                       
                            int      baseType   = iwElt->baseType;
                            bool     isBaseTy   = iwElt->isBaseTy;
                            uint8_t  nptr[2]    = {iwElt->nptr[0], iwElt->nptr[1]};
                            uint64_t size       = iwElt->size;


                            /* then replace element */
                            iwElt->replace(extIWElt);

                            /* and finally restore struct-related fields */
                            iwElt->idx        = idx;
                            iwElt->tyStr      = tyStr;
                            iwElt->name       = name;
                            iwElt->structName = structName;
                            iwElt->fieldName  = fieldName;
                            iwElt->off        = off;
                            iwElt->baseType   = baseType;
                            iwElt->isBaseTy   = isBaseTy;
                            iwElt->nptr[0]    = nptr[0];
                            iwElt->nptr[1]    = nptr[1];
                            iwElt->size       = size;
                        }
                    }

                    iwElt->attr = mergeAttributes(iwElt->attr, extIWElt->attr);
                    
                    emph(v2) << "Interwork Element stage 4: " << iwElt->dump() << "\n";
                    
                    extIWElt->setByExt = true;


                    if (extIWElt->depTy != interwork::Dep_none) {
                        iwElt->depTy     = extIWElt->depTy;
                        iwElt->depID     = extIWElt->depID;
                        iwElt->depIDInit = extIWElt->depIDInit;
                    }

                    if (extIWElt->funcptr) {        // function pointer?
                        info(v2) << "Function Pointer: " << extIWElt->funcptr->dump() << "\n";

                        /* adjust function pointer type */
                        iwElt->funcptr              = extIWElt->funcptr;
                        iwElt->baseType             = interwork::Ty_funcptr;
                        iwElt->isBaseTy             = true;     
                        iwElt->nptr[iwElt->nptrIdx] = 0;
                    }

                } else {                            // this should never happen
                    //throw FuzzGenException("backwardSlicing(): Cannot find interwork element");                
                }
            }
        }
    
        emph(v2) << "Interwork Element final stage: " << iwElt->dump() << "\n";
    }


    // --------------------------------------------------------------------- //
    //                         * Final adjustment *                          //
    // --------------------------------------------------------------------- //
    /* do this for the 0-depth backward slicing only (right before we return) */
    if (!depth) {
        info(v1) << "Adjusting the final type ...\n";

        // When we have cases like api_call(foo.a), we don't want to return the
        // iwArg for foo, but the iwElt for foo.a instead.

        if (interwork::Argument *iwElt = findIWElement(D_bkp, iwArg)) {
            if (iwArg != iwElt) {                   // mismatch?
                info(v1) << "Switching to element: " << iwElt->dump() << "...\n";

                iwArg = iwElt;                      // update argument to point to the element

                iwArg->hasFakeDep = true;           // we may have a fake dependence here
            }
        }


        /* due to many adjustments in iwArg, some fields may be inconsistent. Fix them */ 
        if (iwArg->isBaseTy) {
            iwArg->sz.clear();                      // basic types don't need these fields
            iwArg->nsz        = 1;
            iwArg->structName = "";
            iwArg->fieldName  = "";
            iwArg->prefix     = ' ';
            iwArg->off        = 0;
            iwArg->nptrIdx    = 0;
        }

        iwArg->setByExt = 1;                        // original argument always set by external
    }


    info(v0) << "Backward slice finished." << "\n";


    return BWSLICE_RETVAL_SUCCESS;
}



// ------------------------------------------------------------------------------------------------
// Implement a basic return value analysis.
//
void Backward::retValAnalysis(interwork::APICall *APICall, const CallInst *call) {

    info(v0) << "Return value analysis started." << "\n";

    /* base check */
    if (APICall == nullptr) {
        fatal() << "retValAnalysis(): NULL APICall object!\n";
        return;
    }


    // --------------------------------------------------------------------- //
    //                        * Find store's alloca *                        //
    // --------------------------------------------------------------------- //
    deque<const Instruction *> D;                   // data flow through alloca
    int                        status;    
    const Value                *stVal = nullptr;

    /* check the alloca of the return value as well */
    for (auto user : call->users()) {
        if (const StoreInst *st = dyn_cast<StoreInst>(user)) {
            stVal = st->getPointerOperand();
        }
    }


    // --------------------------------------------------------------------- //
    //       * If it's stored in a struct, find the element sequence *       //
    // --------------------------------------------------------------------- //
    if (stVal) {
         info(v2) << "Store pointer found:" << *stVal << "\n";

        if (const AllocaInst *alloca = findAlloca(stVal, D, status)) {
            info(v2) << "Alloca found:" << *alloca << "\n";

            /* get base type */
            string baseTy = Dig::getBaseTypeStr(alloca->getType());

            /* base type already analysed? (it should as return value is stored somewhere) */
            if (baseIwArg.find(baseTy) != baseIwArg.end()) {
                if (interwork::Element *iwElt = findIWElement(D, baseIwArg[baseTy])) {

                    /* build element sequence */
                    for (APICall->retvalSeq=""; iwElt->parent; 
                         APICall->retvalSeq+=to_string(iwElt->idx) + "-", iwElt=iwElt->parent)
                    { }

                    info(v2) << "Return value sequence found: '" << APICall->retvalSeq << "'\n";
                }
            }
        }
    }

    info(v0) << "Return value analysis finished." << "\n";
}

// ------------------------------------------------------------------------------------------------
