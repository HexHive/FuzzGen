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
 * failure.cpp
 *
 * TODO: Write a small description.
 *
 */
// ------------------------------------------------------------------------------------------------
#include "failure.h"



// ------------------------------------------------------------------------------------------------
// Convert an llvm CmpInst predicate to a C++ operator (this function is static).
//
string Failure::toOperator(int predicate) {
    switch (predicate) {
      case CmpInst::Predicate::ICMP_EQ:
        return "==";

      case CmpInst::Predicate::ICMP_NE:
        return "!=";

      case CmpInst::Predicate::ICMP_UGT:
      case CmpInst::Predicate::ICMP_SGT:
        return ">";

      case CmpInst::Predicate::ICMP_UGE:
      case CmpInst::Predicate::ICMP_SGE:
        return ">=";

      case CmpInst::Predicate::ICMP_ULT:
      case CmpInst::Predicate::ICMP_SLT:
        return "<";

      case CmpInst::Predicate::ICMP_ULE:
      case CmpInst::Predicate::ICMP_SLE:
        return "<=";
    }

    throw FuzzGenPredicateException("Predicate not supported");
}



// ------------------------------------------------------------------------------------------------
// Invert a predicate.
//
int Failure::invert(int predicate) {
    switch (predicate) {
      case CmpInst::Predicate::ICMP_EQ:  return CmpInst::Predicate::ICMP_NE;
      case CmpInst::Predicate::ICMP_NE:  return CmpInst::Predicate::ICMP_EQ;

      case CmpInst::Predicate::ICMP_UGT: return CmpInst::Predicate::ICMP_ULE;
      case CmpInst::Predicate::ICMP_UGE: return CmpInst::Predicate::ICMP_ULT;
      case CmpInst::Predicate::ICMP_ULT: return CmpInst::Predicate::ICMP_UGE;
      case CmpInst::Predicate::ICMP_ULE: return CmpInst::Predicate::ICMP_UGT;

      case CmpInst::Predicate::ICMP_SGT: return CmpInst::Predicate::ICMP_SLE;
      case CmpInst::Predicate::ICMP_SGE: return CmpInst::Predicate::ICMP_SLT;
      case CmpInst::Predicate::ICMP_SLT: return CmpInst::Predicate::ICMP_SGE;
      case CmpInst::Predicate::ICMP_SLE: return CmpInst::Predicate::ICMP_SGT;
    }

    throw FuzzGenPredicateException("Predicate not supported");
}



// ------------------------------------------------------------------------------------------------
// Given a basic block, find the number of basic blocks that are reachable from it. When function
// encounters calls such as "exit()", it should stop counting. This is a challenge as CFG is
// "coarse" grained (basic blocks don't break on function calls). To deal with that, function
// looks for *a* path (explored through BFS) that terminates "naturally". A path terminates
// naturally, when it reaches the end of the function. On the other hand, when a path leads to 
// a) an already visited block or b) an "exit()" call, it cannot be used to return to the caller
// function (in the 1st case, path either loops or it "merges" with another path that may or may
// not terminate naturally, so it's up to the other path).
//
// When a function does not have any paths that terminate naturally, it means that it never
// returns. Hence, the path in the caller function also cannot terminate naturally (termination
// propagates). Thus, we do not visit the successors of a basic block, when that basic block
// contains any calls to functions that do not return. This function is recursive.
//
bool Failure::blkCntRecursive(const BasicBlock *entry, unsigned &N, 
        map<const BasicBlock*, bool> &visited) {

    queue<const BasicBlock*>     Q;                 // BFS queue
    bool terminates = false;                        // initially function does not terminate
    
    
    Q.push(entry);                                  // start with entry BB
    visited[entry] = 0;
    N = 0;                                          // clear counter    


    /* do a BFS to traverse CFG */
    while (!Q.empty()) {
        const BasicBlock *blk = Q.front();          // get next BB        
        Q.pop();                                    // pop it from queue

        bool termBlk = false;                       // originally block is not a terminator
        ++N;                                        // update counter (1 more block found!)


        /* check whether current block is a terminator block */
        // iterate over call instructions in current basic block
        for (BasicBlock::const_iterator ii=blk->begin(); ii!=blk->end(); ++ii) {
            if (const CallInst *call = dyn_cast<CallInst>(ii)) {

                const Function *callee = call->getCalledFunction();
                if (!callee) continue;              // skip empty callees
                
                if (callee->getName() == "exit") {                    
                    termBlk = true;                 // (terminator block) 
                    break;                          // path does not terminate naturally
                }


                /* if function's body is in current module */
                if (!callee->isDeclaration()) {
                    unsigned M;


                    /* recursively explore callee */
                    bool rval = blkCntRecursive(&callee->getEntryBlock(), M, visited);
                    N += M;                         // update block count

                    if (!rval) {                    // if callee does not terminate naturally   
                        termBlk = true;             // => terminator block
                        break;
                    }
                }
            }                
        }


        /* if block is a terminator stop exploring current path */
        if (!termBlk) {
            /* look for adjacent BBs in CFG */
            const TerminatorInst *ti = blk->getTerminator();


            /* if block has no successors, then path terminates naturally */
            if (ti->getNumSuccessors() == 0) {
                terminates = true;                  // function does terminate
            }

            /* get BB's terminator instruction and look for successor BBs */
            for (unsigned i=0; i<ti->getNumSuccessors(); ++i) {
                const BasicBlock *succ = ti->getSuccessor(i);


                if (visited.find(succ) == visited.end()) {                    
                    visited[succ] = true;           // mark node
                    Q.push(succ);
                }
            }
        }
    }

    /* if function terminates return true */
    return terminates;
}



// ------------------------------------------------------------------------------------------------
// This is simply a wrapper around exploreRecursive().
// 
unsigned Failure::blkCnt(const BasicBlock *entry) {
    map<const BasicBlock*, bool> visited;                   // use 1 visited forall recursions
    unsigned N = 0;
    

    blkCntRecursive(entry, N, visited);                      // invoke the recursive version

    return N;
}



// ------------------------------------------------------------------------------------------------
// Check whether a branch satisfies the failure heuristic. If heuristic is satisfied, function
// returns true and val/op arguments are set accordingly. Otherwise function returns false and
// the values of val/op are undefined.
//
// The Failure Heuristic is applied on branch instructions and aims to detect when a branch
// is "failure" branch. So a branch indicates a failure when:
//
//  1. A compare instruction has a user to this branch (immediate or not).
//
//  2. Compare instruction does the comparison against a constant.
//
//  3. The number of BBs that can be explored from the one branch (e.g., TAKEN), is much
//     smaller than the number of BBs that can be explored in the other branch (e.g., NOT TAKEN).
//
bool Failure::isFailure(const BranchInst *br, const CmpInst *cmp, uint64_t &val, int &op) {
    if (!br || !cmp) return false;                  // base checks first

    if (!cmp->isIntPredicate()) {                   // only integers are supported
        fatal() << "Non integer predicates are not supported (yet). Much sad.\n";
        fatal() << *cmp << "\n";
        return false;
    }

    /* try to get the constant operand (if exists) */
    for (User::const_op_iterator jj=cmp->op_begin(); jj!=cmp->op_end(); ++jj) {
        bool isConst = false;

        /* check if value is constant */
        if (const ConstantInt *ci = dyn_cast<ConstantInt>(jj)) {
            isConst = true;
            val   = ci->getLimitedValue();          // get compared value

        } else if (dyn_cast<ConstantPointerNull>(jj)) {
            isConst = true;
            val   = 0;                              // NULL pointer           
        }
         

        if (isConst) {
            /* explore remaining CFG for TAKEN/NOT TAKEN cases */
            unsigned n1 = blkCnt(br->getSuccessor(0)),
                     n2 = blkCnt(br->getSuccessor(1));


            op  = cmp->getPredicate();              // and operator

            if (n2 == 1 || n1 > n2*FAILURE_HEURISTIC_FACTOR) {
                /* the metric of TAKEN is much bigger -> NOT TAKEN is failure */
                try {
                    op = invert(op);                // invert operator
                } catch(FuzzGenPredicateException &e) {
                    fatal() << "An exception was thrown: " << e.what() << ".\n";
                    return false;
                }

                return true;                        // heuristic is satisfied

            } else if (n1 == 1 || n2 > n1*FAILURE_HEURISTIC_FACTOR) {
                /* the metric of NOT TAKEN is much bigger -> TAKEN is failure */
                return true;                        // heuristic is satisfied
            }
        }
    }

    return false;                                   // heuristic is not satisfied
}



// ------------------------------------------------------------------------------------------------
// Check whether the comparison value is originated from call's return value.
//
bool Failure::isRelevantCmp(const CmpInst *cmp, const CallInst *call) {
    const AllocaInst *alloca = nullptr;
    const Value      *val    = cmp;

    /* find alloca's return value (assume it exists) */
    for (const User *user : call->users()) {
        if (const StoreInst *st = dyn_cast<StoreInst>(user)) {

            if ((alloca = dyn_cast<AllocaInst>(st->getPointerOperand()))) {

                info(v3) << "Alloca found: " << *alloca << "\n";
                break;
            }
        }
    }


    /* while value is an instruction, follow the operand chain */
    while (const Instruction *inst = dyn_cast<Instruction>(val)) {
        unsigned n_inst_ops = 0;                    // number of Instruction operands

        for (auto &ii : inst->operands()) {         // for each operand
            if (dyn_cast<Instruction>(ii)) {        // if it's an instruction
                val = ii;                           // use it as the next value
                ++n_inst_ops;
            }

            /* otherwise, ii can be a constant value */
        }

        /* if there are no more or >1 instructions, we don't know if cmp and alloca are relevant */
        if (n_inst_ops != 1) {
            return false;
        }

        /* if we hit a call, we can't "move" from return value to the argument */
        if (val == call) {
            break;
        }
    }


    if (val == alloca || val == call) {
        return true;                                // yes! they are relevant!
    }

    return false;
}


// ------------------------------------------------------------------------------------------------
// Find if function's return value (if exists) correspond to an error code and extract that error
// code. The simplest way to do this is to look for comparison with constants in current block.
//
// TODO: This approach does not work when there are multiple error codes: if (ret == 0 || ret > 17)
//
bool Failure::findErrorValues(const CallInst *call, vector<uint64_t> &vals, vector<string> &ops) {
    const BasicBlock *blk   = call->getParent();    // basic block that contains call instruction
    const Instruction *prev = nullptr;              // previous instruction
    bool skipMode = true;                           // initially, we're in skip mode

    vals.clear();                                   // clear values
    ops.clear();                                    // and operators for Failure Heuristic    


    /* iterate over each instruction*/
    for (BasicBlock::const_iterator ii=blk->begin(); ii!=blk->end(); prev=&*ii++) {

        /* skip all instructions in the block before call */
        if (dyn_cast<CallInst>(ii) == call) {
            skipMode = false;                       // disable skip mode
        }
        else if (skipMode) continue;


        /* look for a compare instruction followed by a branch */
        if (const BranchInst *br = dyn_cast<BranchInst>(ii)) {
            if (const CmpInst *cmp = dyn_cast<CmpInst>(prev)) {

                /* if compare is relevant and branch is conditional (we don't care about others) */
                if (isRelevantCmp(cmp, call) && br->isConditional()) {
                    uint64_t val;
                    int      op;

                    /* apply failure heuristic */
                    if (isFailure(br, cmp, val, op)) {
                        vals.push_back(val);
                        ops.push_back(toOperator(op));

                        info(v1) << "    Failure Heuristic is satisfied when: "
                                 << toOperator(op) << " " << val << "\n";

                        return true;                // our job ends here
                    }
                }
            }
        }
    }

    return false;                                   // no return values found
}

// ------------------------------------------------------------------------------------------------
