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
 * layout.h
 *
 * Header file for layout.cpp.
 *
 */
// ------------------------------------------------------------------------------------------------
#ifndef LIBRARY_LAYOUT_H
#define LIBRARY_LAYOUT_H

#include "common.h"                                 // local includes
#include "interwork.h"
#include "root.h"
#include "dig.h"

#include "llvm/Pass.h"                              // llvm includes
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/User.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Analysis/Passes.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/Interval.h"
#include "llvm/Analysis/PostDominators.h"

#include <typeinfo>                                 // c++ includes
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <string>

#include <list>
#include <map>
#include <stack>
#include <deque>
#include <vector> 
#include <algorithm>

#include <boost/graph/graph_traits.hpp>             // boost libraries
#include <boost/graph/adjacency_list.hpp>
#include <boost/property_map/property_map.hpp>
#include <boost/graph/dominator_tree.hpp>
#include <boost/graph/copy.hpp>

#define UID_INVALID 0x0000ffff

using namespace std;
using namespace boost;
using namespace llvm;


// ------------------------------------------------------------------------------------------------
// * Abstract API Dependence Graph Node*
//
// Elements of an AADG node.
//
class AADGNode {
public:
    /* node attributes */
    enum nodeAttr {
        ATTR_NONE=0x00, 
        ATTR_IS_ROOT=0x01, 
        ATTR_IS_LEAF=0x02, 
        ATTR_NEW=0x10,
        ATTR_COMMON=0x20, 
        ATTR_IGNORE=0x80
    };


    unsigned           uid;                     // a unique ID
    unsigned           funID;                   // function ID (embedded functions have the same value)

    const CallInst     *inst;                   // current instruction
    const BasicBlock   *bb;                     // current basic block

    bool               hasFailure;              // true iff Failure Heuristic is satisfied
    vector<uint64_t>   val;                     // check return value against this value
    vector<string>     op;                      // using this operator
    int                attr;                    // node attributes
    interwork::APICall *APICall;                // interwork object for call instruction


    /* class constructor */
    AADGNode() : uid(0), funID(0), inst(nullptr), bb(nullptr), hasFailure(false) { }

    /* clear all fields */
    void clear() {
        uid        = 0;
        funID      = 0;
        inst       = nullptr;
        bb         = nullptr;
        hasFailure = false;
        attr       = ATTR_NONE;
        APICall    = nullptr;
        val.clear();
        op.clear();
    }
};



// ------------------------------------------------------------------------------------------------
// * AADG types *
//
// Boost type definitions for AADG
//

/* directed graph type */
// setS = no parallel edges, bidirectionalS = in_edges()
typedef adjacency_list<setS, vecS, bidirectionalS, AADGNode> Graph;

/* edge iterator types */
typedef graph_traits<Graph>::edge_iterator     edge_iterator;
typedef graph_traits<Graph>::in_edge_iterator  in_edge_iterator;
typedef graph_traits<Graph>::out_edge_iterator out_edge_iterator;

/* vertex iterator type */
typedef graph_traits<Graph>::vertex_iterator vertex_iterator;

/* vertex descriptor type */
typedef graph_traits<Graph>::vertex_descriptor vertex_t;


/* vertex descriptor type */
typedef graph_traits<Graph>::vertex_descriptor vertex_t;
typedef graph_traits<Graph>::edge_descriptor edge_t;


/* property to index and iterate over vertices */
typedef typename property_map<Graph, vertex_index_t>::type property_map_t;
typedef typename boost::iterator_property_map<vector<vertex_t>::iterator, property_map_t> 
                    property_iterator;

/* adjacency list as a vector of lists */
typedef vector<list<int>> adjacency_list_t;



// ------------------------------------------------------------------------------------------------
// * Layout module *
//
// Build the fuzzer layout
//
class Layout {
public:
    Graph              AADG;                        // Abstract API Dependence Graph
    // adjacency_list_t domTree;                    // dominator tree
    adjacency_list_t   pools;                       // function pools
    map<vertex_t, int> iPools;                      // inverse index for function pools


    /* class constructor */
    Layout(const Module &, DominatorTree *, set<string> &, vector<interwork::APICall *> &);
    
    /* check whether an AADG edge is a backward edge  */
    bool isBackwardEdge(vertex_t, vertex_t);

    /* check whether there a path between 2 AADG vertices in CFG */
    bool isCFGReachable(vertex_t, vertex_t);

    /* visualize AADG */
    bool visualizeAADG(const string filename);

    // /* visualize Dominator Tree */
    // bool visualizeDomTree(const string filename);

    /* return the root node of AADG (is unique) */
    vertex_t AADGroot();

    /* return the size of the AADG */
    unsigned AADGsize();

    /* return the number of edges in the AADG */
    unsigned AADGedges();

    /* find backward edges in AADG */
    void findBackEdges();

    /* Delete a node from AADG */
    bool deleteNode(vertex_t);

    /* create the fuzzer layout */
    bool makeAPICallLayout(const Function &);

    /* update the fuzzer layout */
    void updateAPICallLayout();


private:
    const Module                &module;            // LLVM module
    DominatorTree               *CFG_domTree;       // CFG dominator tree
    set<string>                 &libAPI;            // set of API functions
    vector<interwork::APICall*> &APICalls;          // APICall object from internal module
    map<pair<int, int>, bool>   backEdges;          // AADG's backward edges
    set<string>                 AADGCallStack;      // call stack to catch recursions in AADG


    /* create the AADG */
    size_t makeAbstractAPIDependenceGraph(const Function &, Graph &, int);

    // /* build the dominator tree */
    // adjacency_list_t makeDominatorTree(Graph &);
    // 
    // /* create the pools from dominator tree */
    // adjacency_list_t makePools(adjacency_list_t &);

    /* create the pools from dominator tree */
    adjacency_list_t makePools(Graph &);

    /* find the APICall object for a given API function */
    interwork::APICall *findAPICall(string name);

    /* find the AADG node for a given call instruction */
    AADGNode *findAADGNode(const CallInst *);

    /* search for nodes inside AADG (slow) */
    vertex_t find(const BasicBlock *bb, Graph &G);
    vertex_t find(unsigned uid, Graph &G);

    /* generate a padding of n tabs */
    inline string pad(int n) {
        string indentation;

        for (int i=0; i<n<<2; ++i, indentation+=" ")
            { }

        return indentation;
    }
};


// ------------------------------------------------------------------------------------------------
#endif
