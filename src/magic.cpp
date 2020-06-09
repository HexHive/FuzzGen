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
 * magic.cpp
 *
 * TODO: Write a small description.
 *
 */
// ------------------------------------------------------------------------------------------------
#include "magic.h"
#include "dig.h"                                    // needed for Dig::getStructName()


// ------------------------------------------------------------------------------------------------
// Globals
//
const set<string> Magic::sizeNames = {              // common names to represent sizes
    "size",   "Size",   "sz",  "Sz",
    "length", "Length", "len", "Len",
    "buflen",
    "num_bytes", "num_Bytes",
    "n", "N"
};



// ------------------------------------------------------------------------------------------------
// Class constructor.
//
Magic::Magic(Context *ctx, deque<unsigned> &structOff) :
        ctx(ctx), structOff(structOff), analysisTy(ctx->flags & FLAG_ANALYSIS) { }



// ------------------------------------------------------------------------------------------------
// Clear visited node (needed for recursion
//
void Magic::clear() {
    funcVisited.clear();
}



// ------------------------------------------------------------------------------------------------
// Check if an argument represents an array. IR doesn't have this information, so look it up from
// library's metadata.
//
inline bool Magic::isArray(const Argument &arg) {
    string func = arg.getParent()->getName();
    string name = arg.getName();


    if (name == "") {
         if (ctx->paramNames.find(func) != ctx->paramNames.end() &&
             ctx->paramNames[func].size() > arg.getArgNo()) {
                name = ctx->paramNames[func][arg.getArgNo()];
        } else {
                return false;
        }
    }        

    return ctx->arrayRef[func].find(name) != ctx->arrayRef[func].end();
}



// ------------------------------------------------------------------------------------------------
// Given an argument, get the preceding argument.
//
inline const Argument &Magic::getPreceding(const Argument &arg) const {

    /* iterate over arguments */
    for (const auto &a : arg.getParent()->args()) {
        if (a.getArgNo() + 1 == arg.getArgNo()) {
            return a;                               // argument found!
        }
    }

    return arg;                                     // failure. Return argument itself
}



// ------------------------------------------------------------------------------------------------
// Perform a data flow analysis on the argument, along with a simple alias analysis.
//
// A few notes on the casting problem: When type casting is used for some argument, attributes are
// messed up. For instance consider a struct object that is cast to void* (i8*). Although 
// individual elements of the struct may have different attributes, the dataflow analysis will
// coalesce all of them into a single as the type is i8. If struct.a is predefined with values 
// {3, 5, 12}, struct.b is invariant and struct.c is random, the analysis will say that struct
// object is random.
//
// To overcome this issue, we look for bitcast instruciton. Function does not set any attributes
// (DISABLED mode), until there's a casting to the desired struct type. After that, function
// enters OFF mode, where still no attributes are set, until getelementptr access the right
// element. At this point function enters ON mode and only then attributes can be set.
//
// Although this simple idea works great, aliases are still a problem: 
//
//          pu4_api_ip = (UWORD32 *)pv_api_ip;
//          e_cmd = (IVD_API_COMMAND_TYPE_T)*(pu4_api_ip + 1);
//          switch((WORD32)e_cmd)
//          {
//          case IVD_CMD_CREATE:
//          case IVD_CMD_REL_DISPLAY_FRAME:
//          case IVD_CMD_SET_DISPLAY_FRAME:
//          ...
//
//
// Here, the second element of pu4_api_ip struct is accessed through an integer pointer. The
// casting to the struct type and the GEP instructions are bypassed, so our analysis fails to
// catch all these predefined contants (IVD_CMD_CREATE, IVD_CMD_REL_DISPLAY_FRAME and so on).
//
// TODO: Check the text again.
//
template<typename T>
MagicData<T> *Magic::dataflowAnalysis(const Argument &arg, const AllocaInst *alloca, int depth) {
    stack<StackFrame*> S;                           // stack for "recursions"
    list<StackFrame*>  defunct;                     // defunct nodes (needed for destruction)

    StackFrame   *last = nullptr,                   // last visited node (not parent)
                 *temp;                             // temporary node
    bool         read  = false;                     // true when argument's value is being read
    
    MagicData<T> *md   = new MagicData<T>();        // magic data
    

    info(v3) << "  Starting Data Flow analysis on '" << arg.getParent()->getName() << "' " 
             << "at depth:" << depth << " from:" << *alloca << "\n";

    // Don't clear 'visited', as it's global for all alloca's
  
    /* push alloca on stack first */
    temp = new StackFrame(dyn_cast<Value>(alloca), setAttrMode);
    S.push(temp);
    defunct.push_back(temp);


    /* do a DFS (w/o recursion) */
    /* follow users of users starting from instructions in the initial set */

    // because parent pointers are used, we cannot delete last ptr in each iteration
    // instead we collect all defunct pointers and we kill them at the end of the function
    while (!S.empty()) {
        StackFrame *curr = S.top();                 // get top node
        S.pop();

        /* make sure that instruction has not been visited again */
        if (visited.find(curr->inst) != visited.end()) {
            continue;              
        }

        visited[curr->inst] = true;                 // mark instruction as visited
        md->mode    = curr->mode;                   // update mode
        setAttrMode = curr->mode;


        /* if ATTR_RANDOM is set, there's no point for further processing */
        if ((md->attr & 0xff) == ATTR_RANDOM) {            
            info(v3) << "Attribute is already set to 'random'. Halt Data Flow analysis.\n";
            break;                                  // ATTR_RANDOM dominates everything
        }

        info(v3) << "    Visit(" << curr->depth << ", " << curr->n     << ", " 
                 << curr->read  << ", " << curr->mode  << ") : " 
                 << md->attr    << " |" << *curr->inst << "\n";


        /* check if current branch is different from the previous one */
        if (last && curr->parent != last) {
            Type *ldty = last->inst->getType();

            // TODO: Check this again.
            if (last->read && dyn_cast<LoadInst>(last->inst) && ldty->isIntegerTy()) {
                read = true;

                fatal() << "A buffer read has been detected from parent.\n";
            }
        }


        // --------------------------------------------------------------------- //
        //                       * Casting Instructions *                        //
        // --------------------------------------------------------------------- //
        if (const BitCastInst *bc = dyn_cast<BitCastInst>(curr->inst)) {
            if (curr->mode == SET_ATTR_MODE_ON) {
                /* no need for any action */
            } else {

                /* check if casting is done to the original type */
                if (Dig::getStructTy(bc->getDestTy()) == origTy) {
                    info(v3) << "  Casting to the original type: " << *bc->getSrcTy()
                             << " -> " << *bc->getDestTy() << "\n";

                    /* update mode so GEP can switch mode to ON */
                    curr->mode  = SET_ATTR_MODE_OFF;
                    setAttrMode = curr->mode;
                } // else if(curr->mode == SET_ATTR_MODE_ON) {
                  //     curr->mode = SET_ATTR_MODE_OFF;
                  // }                
            }
        }


        // --------------------------------------------------------------------- //
        //                        * Compare Instructions *                       //
        // --------------------------------------------------------------------- //
        else if (const CmpInst *cmp = dyn_cast<CmpInst>(curr->inst)) {

            /* check if argument is directly compared against an integer with == or != */
            if (cmp->isIntPredicate()) {// && (cmp->getPredicate() == CmpInst::Predicate::ICMP_EQ ||
                    // cmp->getPredicate() == CmpInst::Predicate::ICMP_NE)) {

                /* try to get the constant operand */
                for (User::const_op_iterator jj=cmp->op_begin(); jj!=cmp->op_end(); ++jj) {
                    if (const ConstantInt *ci = dyn_cast<ConstantInt>(jj)) {
                        
                        md->addAttr(ATTR_PREDEFINED);
                        md->addPredefined( ci->getSExtValue() );
                        
                        if (curr->mode == SET_ATTR_MODE_ON) {
                            info(v2) << "    Predefined Value '" << ci->getSExtValue()
                                     << "' found! (" << curr->mode << ")\n";
                        }
                    }
                }

                /*
                 * TODO: Do the same for >, >=, <, <= operators exactly as you did in
                 *       External::isFailure(). But this time add 2 predefined values:
                 *       If for instance argc > 3 => add a value greater than 3 and 1 
                 *       smaller than 3.
                 *
                 *       To further improve you can use the failure heuristic, to discard
                 *       any of these 2 values that corresponds to an invalid value.
                 */
            }

            /* do the same for floating point */
            else if (cmp->isFPPredicate() &&
                    (cmp->getPredicate() == CmpInst::Predicate::FCMP_OEQ ||
                     cmp->getPredicate() == CmpInst::Predicate::FCMP_ONE)) {

                for (User::const_op_iterator jj=cmp->op_begin(); jj!=cmp->op_end(); ++jj) {
                    if (const ConstantFP *fp = dyn_cast<ConstantFP>(jj)) {

                        md->addAttr(ATTR_PREDEFINED);
                        md->addPredefined( fp->getValueAPF().convertToDouble() );

                        if (curr->mode == SET_ATTR_MODE_ON) {
                            info(v2) << "    Predefined Value '" 
                                     << fp->getValueAPF().convertToDouble()
                                     << "' found! (" << curr->mode << ")\n";
                        }
                    }
                }
            }
        }


        // --------------------------------------------------------------------- //
        //                        * Switch Instructions *                        //
        // --------------------------------------------------------------------- //
        else if (const SwitchInst *sw = dyn_cast<SwitchInst>(curr->inst)) {
            uint64_t lastVal = 0;

            /* get constants from each case */
            for (SwitchInst::ConstCaseIt jj=sw->case_begin(); jj!=sw->case_end(); ++jj) {
                const Value *value = dyn_cast<Value>(jj->getCaseValue());

                if (const ConstantInt *ci = dyn_cast<ConstantInt>(value)) {

                    md->addAttr(ATTR_PREDEFINED);
                    md->addPredefined( ci->getSExtValue() );

                    lastVal = ci->getSExtValue();
        
                    if (curr->mode == SET_ATTR_MODE_ON) {
                        info(v2) << "    Predefined Value '" << lastVal << "' found (" 
                                 << curr->mode << ")\n";
                    }
                }
            }

            /* deal with "default" case: Add 1 more predefined value different from any other */
            for (int i=10000; i<10100; ++i) {
            // for (int i=0; i<100; ++i) {
                if (!md->inPredefined(lastVal + i)) {
                    md->addPredefined(lastVal + i);
                    break;
                }
            }
        }


        // --------------------------------------------------------------------- //
        //                      * Arithmetic Instructions *                      //
        // --------------------------------------------------------------------- //
        else if (const BinaryOperator *bop = dyn_cast<BinaryOperator>(curr->inst)) {
            /* sometimes ANDs are used in address calculation, so we can skip them */
            // if (!strcmp(bop->getOpcodeName(bop->getOpcode()), "and")) {
            //
            // }

            /* argument is used in calculations */
            md->addAttr(ATTR_RANDOM);               // argument is random
        }


        // --------------------------------------------------------------------- //
        //                         * Load Instructions *                         //
        // --------------------------------------------------------------------- //
        else if (const LoadInst *ld = dyn_cast<LoadInst>(curr->inst)) {
            Type *ldty = ld->getType();

            curr->read = true;                      // read encountered
            md->addAttr(ATTR_INVARIANT);            // argument is not dead; move it to the next level

            /* We can actually detect: allo->foo[ allo->foo[2] ] = 20; */

            /* if loaded value has a basic type*/
            if (ldty->isIntegerTy() || ldty->isFloatTy() || ldty->isDoubleTy()) {                                
                info(v3) << "    A buffer read has been detected from LoadInst.\n";

                read = true;                        // argument is being read!
            }
        }


        // --------------------------------------------------------------------- //
        //                        * Store Instructions *                         //
        // --------------------------------------------------------------------- //
        else if (const StoreInst *st = dyn_cast<StoreInst>(curr->inst)) {

            /* if the flow came from the Value operand, we have an alias! */
            if (st->getValueOperand() == dyn_cast<Value>(curr->parent->inst)) {

                if (const AllocaInst *alloca2 = dyn_cast<AllocaInst>(st->getPointerOperand())) {
                    skippedStores[st] = true;       // mark store, so you won't visit it again

                    info(v3) << "  Alias found. Switching to a new alloca ...\n";

                    /* recursively follow the alias and coalesce the "magic" results */                    
                    coalesce(md, dataflowAnalysis<T>(arg, alloca2, depth));
                } else {
                    /* forget about it */
                }                
            } else {
                /* we don't know what the store value is. Just fuzz it */
                /* OPT: figure out from where the store value comes from and fuzz this instead */
                if (skippedStores.find(st) == skippedStores.end()) {
                    // md->addAttr(ATTR_RANDOM);   // ok make it random
                    
                    /* argument is used to hold output */
  //                  md->addAttr(ATTR_WRITEONLY);
//                    md->attr &= 0xff00;           // clear other attributes
                    md->addAttr(ATTR_RANDOM);


                    break;
                }
            }
        }


        // --------------------------------------------------------------------- //
        //                         * Call Instructions *                         //
        // --------------------------------------------------------------------- //
        else if (const CallInst *call = dyn_cast<CallInst>(curr->inst)) {
            /* Argument is being used inside another function */
            
            if (curr->parent == nullptr) {
                fatal() << "Null parent pointer!\n";
                return nullptr;
            }

            // Inspect callee only iff deep analysis is set. This makes sense for predefined
            // and invariant attributes. If attribute has already the random attribute,
            // there's no point for any further analysis (attribute can't be changed)
            if (analysisTy != deep || md->attr == ATTR_RANDOM) {
                continue;                           // skip call
            }

        
            /* find the Argument for the corresponding user */
            const Function *callee = call->getCalledFunction();
            const Use *a1;
            const llvm::Argument *a2;


            /* callee may be a function pointer, so make sure that it's not null */
            if (callee == nullptr) {
                continue;
            }


            info(v3) << "  Calling function '" << callee->getName() << "' ...\n";

            /* iterate over arguments of CallInst and callee in parallel */
            for (a1=call->arg_begin(), a2=callee->arg_begin();
                    a1!=call->arg_end() && a2!=callee->arg_end(); ++a1, ++a2) {

                /* desired argument found? */
                if (dyn_cast<Value>(a1) == dyn_cast<Value>(curr->parent->inst)) {

                    /* loop detection first */
                    if (funcVisited.find(a2) != funcVisited.end()) {
                        remark(v3) << "  Function '" << callee->getName() 
                                   << " 'has already been visited. Skip.\n";

                    } else if (depth < ctx->maxDepth) {
                        remark(v3) << "  Recursively calling argSpaceInference() for deep "
                                   << "argument analysis...\n";

                        funcVisited[ a2 ] = 1;      // mark argument as visited

                        /* start all over again and merge results */
                        coalesce(md, argSpaceInference<T>(*a2, depth + 1));
                    } else {
                        remark(v3) << "Maximum recursion depth has been reached. "
                                   << "Skipping function\n";
                    }

                    break;                          // argument found. Stop here
                }
            }

            /* The user of the call is the return value, so we don't really need to move on */
            continue;
        }


        // --------------------------------------------------------------------- //
        //            * GEP instructions - this is a baby "digInto" *            //
        // --------------------------------------------------------------------- //
        else if (const GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(curr->inst)) {
            Type *ty  = gep->getPointerOperandType();
            bool stop = 0;


            for (auto &ii : gep->indices()) {       // check GEP indices
                // ------------------------------------------------------------
                if (ty->isPointerTy()) {            // pointer type. Dig into
                    ty = dyn_cast<PointerType>(ty)->getElementType();
                }
                // ------------------------------------------------------------
                else if (ty->isArrayTy()) {         // array type. Dig into
                    ty = dyn_cast<ArrayType>(ty)->getElementType();
                }
                // ------------------------------------------------------------
                else if (ty->isStructTy()) {        // struct type. Check offsets
                    

                    if (curr->n >= structOff.size()) {
                        /* the deque has been exhausted. Stop */
                        stop = 1;
                        break;
                    }

                    /* now compare index with the corresponding entry in deque */
                    if (const ConstantInt *off = dyn_cast<ConstantInt>(ii)) {
                        if (structOff[curr->n] != off->getLimitedValue()) {
                            /* GEP doesn't access the desired element */
                            stop = 1;
                            break;
                        }

                        ++curr->n;                  // all good. move on the next index

                        /* dig into the next type of GEP */
                        ty = dyn_cast<StructType>(ty)->getElementType(off->getLimitedValue());
                    }
                }
                // ------------------------------------------------------------
                else {
                    stop = 1;
                    break;
                }
            }

            curr->read = false;                     // GEP cancels read


            /* if we have the right casting and all indices are correct */
            if (curr->n == structOff.size() && curr->mode == SET_ATTR_MODE_OFF) {
                setAttrMode = SET_ATTR_MODE_ON; // you can modify attributes now
                curr->mode  = SET_ATTR_MODE_ON;
            }

            if (stop) {
                /* don't check users for this instruction */
                last = curr;
                continue;
            }
        }

       
        // --------------------------------------------------------------------- //
        //        * Push all users of current instruction to the stack *         //
        // --------------------------------------------------------------------- //     
        for (Value::const_user_iterator usr=curr->inst->user_begin();
                usr!=curr->inst->user_end(); ++usr) {

            temp = new StackFrame(dyn_cast<Value>(*usr), curr);
            ++temp->depth;                          // move 1 step deeper

            S.push(temp);
            defunct.push_back(temp);
        }

        last = curr;                                // set last instruction
    }


    // we don't care if a variable is write-only, as it's not returned
    if (!read) ; // md->addAttr(ATTR_WRITEONLY);


    /* RIP all defunct nodes */
    for (StackFrame *def : defunct) delete def;
    defunct.clear();


    info(v3) << "  Finishing Data Flow analysis on '" << arg.getParent()->getName() << "' " 
             << "from:" << *alloca << "\n";

    return md;
}



// ------------------------------------------------------------------------------------------------
// This is the heart of FuzzGen. This function does its "magic" to determine whether and how an
// argument should be fuzzed. Composite arguments (structs, arrays, pointers etc.) cannot be
// fuzzed directly, so one must break them into basic arguments first. When an argument is a
// struct, magic gets assisted by a special deque that holds the indices that one must follow, in
// order to reach the basic argument (that is being processed) within this struct. Hence magic()
// can be invoked multiple times with the same argument, but with different deque values.
//
// What magic function returns? Magic data of course! Magic data consist of some attributes along
// with some optional auxiliary values. Because the type of these values depends on the type of
// the processed argument, magic data are templated.
//
// Now, the analysis part is simple yet solid. A data dependence analysis based on "users of
// users" is used to determine how an argument is being used inside the function. When _deep_
// analysis is enabled, calling functions (which are called from current function), are
// recursively analyzed as well. That is, if an argument is being passed as an argument to an
// another function (inside the analyzed function), magic() is recursively called for the callee
// and will combine the results.
//
// Besides data dependence analysis, magic() also applies some heuristics to better analyze
// attributes. The most notable one is the "size heuristic", which is used to determine whether
// an argument represents the size of an another buffer. Consider for instance, a fuzzer for
// memcpy:
//
//      void *memcpy(void *dest, const void *src, size_t n);
//
// Blindly fuzzing all the arguments, can go terribly wrong here. By given a random value to "n",
// it will probably become inconsistent with the actual size of "src". When the value of "n" is
// larger than the actual size of "src", memcpy() will read out of bounds, thus resulting in a
// crash. However, this crash is *not* be a real bug. To catch such cases, size arguments should
// not take random values, but instead they should take a value that is consistent with the buffer
// size. Therefore, we can say that an argument represents a size, when:
//
//  1. Argument has an integer type
//
//  2. Argument has a well known name that defines a size (e.g., "length", "size", and so on)
//
//  3. The preceding argument is an array, or is a pointer which has identified as an array
//     by the preprocessor.
//
// When all of 1, 2 and 3 are hold, we can infer that the argument represents the size of an
// array.
//
// Continuing on the same example, there's also another issue: Fuzzer, will put a lot of effort,
// trying to fuzz the "dest" argument, which is not read by memcpy(). Being able to detect
// buffers that are used only to hold output (i.e., write only buffers), is also a good
// optimization, as the values of these buffers, are not used by the function at all.
//
//
// An argument can take one (or more) of the following attributes:
//
//  * dead : Argument isn't used by the function
//
//  * invariant : Argument isn't modified, or values are not derived from it (e.g. file
//                descriptors)
//
//  * predefined : Argument is compared against a set of constant values
//
//  * random : Argument is modified and/or participates in calculations (i.e., values are
//             derived from it)
//
//  * array : Argument is used as an array and not as a reference (pointers only)
//
//  * arraysize : Argument is used to represent the size of another argument (=buffer)
//
//  * writeonly : Argument is used to hold output and no values are read from it. This only
//                makes sense for values that are being returned (pointers)
//
// Note that some arguments are mutually exclusive (e.g., an argument can't be dead and random
// at the same time).
//
// Also, digInto() ensures that magic() is invoked only on basic arguments. If not, all
// computations of magic() are wasted.
//
// Finally, the problem that magic() is called to solve is a very hard problem. For instance,
// aliases can screw up the analysis and unfortunately we cannot do anything about that. Besides
// that, the advantage here, is that if the analysis fails, magic() sets attribute to random.
//
// This gives space for some improvements. Alias Analysis (AA) and Scalar Evolution (SCEV) are
// some analyses that magic() could also apply in order to give more precise results.
//
// TODO: Split comment to dataflowAnalysis()
//
template<typename T>
MagicData<T> *Magic::argSpaceInference(const Argument &arg, int depth) {
    MagicData<T> *md = new MagicData<T>();          // magic data
    string       offStr;                            // string to hold offsets


    /* start with some useful debug information */
    for (auto ii=structOff.begin(); ii!=structOff.end(); offStr+=to_string(*ii++) + " ")
        { }

    info(v3) << "---=[ Entering magic(" << arg << "). Deque: " << offStr << "]=---\n";

    md->setAttr(ATTR_DEAD);                         // initially, argument is dead

    /* if dumb analysis is used, don't utilize argSpaceInference(). Just fuzz everything */
    if (analysisTy == dumb) {
        info(v3) << "Dumb analysis does not need magic().\n";

        md->setAttr(ATTR_RANDOM);                   // everything is random
        return md;
    }


    // --------------------------------------------------------------------- //
    //                            * Heuristics *                             //
    // --------------------------------------------------------------------- //

    /* check whether size heuristic gets satisfied */
    if (arg.hasName() && sizeNames.find(arg.getName()) != sizeNames.end() &&
            arg.getType()->isIntegerTy() &&
            (isArray(getPreceding(arg)) || getPreceding(arg).getType()->isArrayTy())) {

        info(v3) << "Argument represent an array size. Don't fuzz it.\n";

        /* argument represents buffer's size */
        md->setAttr(ATTR_ARRAYSIZE);

        return md;                                  // no further analysis is required
    }

    /* Feel free to add more heuristics here ... */


    // --------------------------------------------------------------------- //
    //                              * Arrays *                               //
    // --------------------------------------------------------------------- //

    /* check if argument is used as array */
    // if (arg.getType()->isArrayTy() || (arg.getType()->isPointerTy() && isArray(arg))) {
    if (arg.getType()->isPointerTy() && isArray(arg)) {
        md->setAttr(ATTR_ARRAY);
    }


    // --------------------------------------------------------------------- //
    //                         * Dataflow Analysis *                         //
    // --------------------------------------------------------------------- //
    if (depth == 0) {                               // do only the first time function is recursive
        visited.clear();                            // clear maps
        skippedStores.clear();
    } 

    for (const User *usr : arg.users()) {           // start from argument's users   
        if (const StoreInst *st = dyn_cast<StoreInst>(usr)) {

            /* find the alloca that holds the argument's value */
            if (const AllocaInst *alloca = dyn_cast<AllocaInst>(st->getPointerOperand())) {
                skippedStores[st] = true;           // mark store to not use it again

                /* start a Data Flow analysis from this alloca */
                coalesce(md, dataflowAnalysis<T>(arg, alloca, depth));

            } else {                                // something is wrong here
                md->setAttr(ATTR_RANDOM);           // set to random and exit
                return md;
            }
        } 
    }


    // --------------------------------------------------------------------- //
    //                       * Print the magic data *                        //
    // --------------------------------------------------------------------- //
    string foo;                                     // you should remane that

    for (auto i=md->predefined.begin(); i!=md->predefined.end(); ++i) {
        foo += to_string(*i) + ", ";
    }

    if (foo.size() > 1) {
        foo.pop_back();
        foo.pop_back();
    } else foo = "-";


    ostringstream oss;
    oss << "0x" << hex << md->attr;

    remark(v3) << "Argument attributes: " << oss.str() << ". Values: " << foo << "\n";

    return md;                                      // return the magic data
}



// ------------------------------------------------------------------------------------------------
// Coalesce two magic data types into a single one.
//
template<typename T>
inline void Magic::coalesce(MagicData<T> *m1, MagicData<T> *m2) {
    int attr = 0;

/*
    string f;
    ostringstream s(f);
    s << hex <<  m1->attr << " : " << m2->attr;
    warning()  << "COALESCE: " << s.str() << "\n";
*/
    if (!m1->attr && !m2->attr) {
        /* do nothing here */
    }

    /* keep write-only attribute only if both have it */
    else if ((!m1->attr || m1->attr & ATTR_WRITEONLY) && 
             (!m2->attr || m2->attr & ATTR_WRITEONLY)) {
        attr |= ATTR_WRITEONLY;
    }

    /* keep array-size attribute only if both have it */
    // else if (m1->attr & m2->attr & ATTR_ARRAYSIZE) {
    else if ((!m1->attr || m1->attr & ATTR_ARRAYSIZE) && 
             (!m2->attr || m2->attr & ATTR_ARRAYSIZE)) {
        attr |= ATTR_ARRAYSIZE;
    }

    /* keep array attribute if any of m1, m2 has it */
    else if ((m1->attr | m2->attr) & ATTR_ARRAY) {
        attr |= ATTR_ARRAY;
    }

    /* predefined, overwrites invariant and random overwrites everything */
    attr |= (m1->attr | m2->attr) & FLAG_ANALYSIS;


    if ((attr & FLAG_ANALYSIS) == ATTR_PREDEFINED) {
        /* merge predefined lists */
        m1->predefined.merge(m2->predefined);
    } else {
        m1->predefined.clear();
    }

    m1->attr = attr;
    delete m2;                                      // m2 is not needed anymore
}



// ------------------------------------------------------------------------------------------------
// Cast a magic data object into an interwork object.
//
template <typename T>
interwork::BaseAttr *Magic::magicToInterwork(MagicData<T> *md, string ty) {

    interwork::Attributes<T> *ba = new interwork::Attributes<T>(md->attr, ty);

    /* copy predefined values */
    for (auto v : md->predefined) {
        ba->push(v);
    }

    return dynamic_cast<interwork::BaseAttr*>(ba);
}



// ------------------------------------------------------------------------------------------------
// A wrapper around the internal analysis.
//
interwork::BaseAttr *Magic::do_magic(Argument &arg, Type *ty, string type) {

 
    if (arg.getType() == ty){
        info(v3) << "No type casting was used.\n";

        origTy      = nullptr;                      // we don't need that
        setAttrMode = SET_ATTR_MODE_ON;             // always update attributes
    } else {
        info(v2) << "Type casting was used: " << *ty << "\n";

        origTy      = ty;                           // wait until this casting is used
        setAttrMode = SET_ATTR_MODE_DISABLED;       // don't update attributes till the right moment
    }
    

    /* this is templated. Dispatch the appropriate function */
    if (type == "int8_t") {
        return magicToInterwork(argSpaceInference<int8_t>(arg), "int8_t");
    } else if (type == "int16_t") {
        return magicToInterwork(argSpaceInference<int16_t>(arg), "int16_t");
    } else if (type == "int32_t") {
        return magicToInterwork(argSpaceInference<int32_t>(arg), "int32_t");
    } else if (type == "int64_t") {
        return magicToInterwork(argSpaceInference<int64_t>(arg), "int64_t");
    } else if (type == "float") {
        return magicToInterwork(argSpaceInference<float>(arg), "float");
    } else if (type == "double") {
        return magicToInterwork(argSpaceInference<double>(arg), "double");
    } else {
        throw FuzzGenException("do_magic(): Unknown type");
    }       
}

// ------------------------------------------------------------------------------------------------
