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
 * layout.cpp
 *
 * TODO: Write a small description.
 *
 */
// ------------------------------------------------------------------------------------------------
#include "layout.h"



// ------------------------------------------------------------------------------------------------
// Class constructor.
//
Layout::Layout(const Module &module, DominatorTree *CFG_domTree, set<string> &libAPI,
        vector<interwork::APICall*> &APICalls) :
        AADG(0), module(module), CFG_domTree(CFG_domTree), libAPI(libAPI),
        APICalls(APICalls) {
}



// ------------------------------------------------------------------------------------------------
// Find the AADG node that corresponds to a given call instruction.
//
AADGNode *Layout::findAADGNode(const CallInst *call) {

    /* iterate over nodes in AADG till you find the call instruction */
    for (vertex_iterator ii=vertices(AADG).first; ii!=vertices(AADG).second; ++ii) {
        vertex_t v = vertex(*ii, AADG);

        if (call == AADG[v].inst) {
            return &AADG[v];                        // node found
        }
    }

    return nullptr;                                 // failure. return NULL
}



// ------------------------------------------------------------------------------------------------
// Given an API function, find its APICall object built by the internal module.
//
interwork::APICall *Layout::findAPICall(string name) {

    for (auto ii=APICalls.begin(); ii!=APICalls.end(); ++ii) {
        if (name == (*ii)->name) {
            return *ii;                             // object found!
        }
    }

    return nullptr;                                 // object not found
}



// ------------------------------------------------------------------------------------------------
// Given a basic block, look for the vertex that corresponds to it.
//
// OPT: This linear search is too bad. We can do much better using hash maps.
//
vertex_t Layout::find(const BasicBlock *bb, Graph &G) {
    /* declare a property to index vertices */
    property_map<Graph, vertex_index_t>::type idx = get(vertex_index, G);


    /* for each vertex in G */
    for (vertex_iterator ii=vertices(G).first; ii!=vertices(G).second; ++ii) {
        if (G[idx[*ii]].bb == bb) {                 // check if BB matches the target

            return idx[*ii];                        // if so return it
        }
    }

    /* this shouldn't happen as by definition, each BB is associated with a vertex */
    throw FuzzGenException("find(): Basic Block doesn't exist in AADG");
}



// ------------------------------------------------------------------------------------------------
// Given an uid, look for the vertex that corresponds to it.
//
// OPT: This linear search is too bad. We can do much better using hash maps.
//
vertex_t Layout::find(unsigned uid, Graph &G) {
    /* for each node in G */
    for (vertex_iterator ii=vertices(G).first; ii!=vertices(G).second; ++ii) {
        vertex_t v = vertex(*ii, G);

        if (G[v].uid == uid) {                      // check if uid matches
            return v;                               // if so return it
        }
    }

    return UID_INVALID;                             // not found
}



// ------------------------------------------------------------------------------------------------
// Create the Abstract API Dependence Graph (AADG). AADG is derived from Control Flow Graph (CFG)
// and therefore these 2 are very similar. Each node in AADG represents a single call to one API
// function. The edges between nodes show the "contorl flow" (exactly as in CFG). However a direct
// edge in AADG can be a long path in CFG. Also function calls are deeply inspected and the
// resulting AADG of the callee is placed directly into the AADG. This might sound a bad idea, but
// the AADG for each function contains only the invoked API calls, so it tends to remain small.
//
// This function is recursive. Function returns the number of nodes that an AADG for a given
// function has.
//
// OPT: Graph merging is linear.
//
size_t Layout::makeAbstractAPIDependenceGraph(const Function &F, Graph &G, int deep) {
    /* ignore functions with no basic blocks */
    if (F.empty()) return 0;

    const BasicBlock             *entry = &F.getEntryBlock();
    std::queue<const BasicBlock*> Q;
    map<const BasicBlock*, bool>  visited;
    unsigned                      uid = 0;          // unique IDs for nodes
    static unsigned               funID = 0;        // unique function ID
    

    /* Recursive functions result in infinity loops. To prevent this we use a call stack */
    // (function names are unique in the same module)
    if (AADGCallStack.find(F.getName()) != AADGCallStack.end()) {
        warning() << "Recursive function found in AADG construction. Ignore it...\n";
        
        return 0;

    } else {
        AADGCallStack.insert(F.getName());          // add function to the call stack
    }



    Q.push(entry);                                  // start with entry BB
    visited[entry] = true;                          // mark it as visited

 
    /* All nodes from the same function have the same funID. When a function is embedded
     * multiple times in AADG, each instance has a different funID. Thus we can distinguish
     * between the nodes of the same function among different function instances.
     */
    ++funID;

    info(v2) << pad(deep) << "* Entering '" << F.getName() << "' (" << funID << ") *\n";



    // --------------------------------------------------------------------- //
    //                       * Clone CFG into an AADG *                       //
    // --------------------------------------------------------------------- //

    /* create an AADG node for each basic block */
    for (auto ii=F.begin(); ii!=F.end(); ++ii) {
        vertex_t v = add_vertex(G);

        G[v].bb    = &*ii;                          // add BB to the vertex
        G[v].uid   = uid++;                         // uid must be unique for this graph
        G[v].funID = funID;                         // function ID (unique per function instance)
        G[v].attr  = AADGNode::ATTR_NONE;           // give no attributes
    }


    /* give entry block the root attribute (i.e., mark it as root) */
    G[find(entry, G)].attr = AADGNode::ATTR_IS_ROOT;


    /* do a BFS to traverse CFG and update AADG */
    while (!Q.empty()) {
        const BasicBlock *blk = Q.front();          // get next AADGNode
        Q.pop();                                    // pop it from queue

        vertex_t n     = find(blk, G),              // get corresponding AADG node
                 n_bkp = n;                         // make a backup of it


        /* for each instruction in the basic block */
        for (auto ii=blk->begin(); ii!=blk->end(); ++ii) {

            /* we only care about call instructions */
            if (const CallInst *call = dyn_cast<CallInst>(ii)) {
                const Function *callee = call->getCalledFunction();

                if (!callee) continue;              // skip empty callees

                // Alternative way to get function name:
                //      string name = call->getOperand(call->getNumOperands() - 1)->getName();


                /* check if called function is part of the API */
                if (libAPI.find(callee->getName()) != libAPI.end()) {

                    // It's possible that a single BB invokes >1 root functions. In that case,
                    // we split the AADG node into 2 and we connect them with a single edge.
                    // At this point node is visited for first time, and thus it has not
                    // outgoing edges yet. So, splitting is trivial.
                    if (!G[n].inst) {
                        G[n].inst = call;           // store call instruction to the AADG node
                    } else {
                        /* there's already a CallInst. Split node. */
                        vertex_t n2 = add_vertex(G);

                        G[n2].inst  = call;
                        G[n2].uid   = uid++;
                        G[n2].funID = G[n].funID;
                        G[n2].attr  = AADGNode::ATTR_NONE;

                        /* add an edge between these two nodes */
                        add_edge(n, n2, G);

                        /* any future references to the same BB should point to the new node */
                        G[n2].bb = blk;
                        G[n].bb  = nullptr;         // zero this to make find() to skip it

                        n = n2;                     // update n to point to the new node
                    }
                } 
                /* otherwise, we have a new function to explore (skip empty callees) */
                else { //if (const Function *callee = call->getCalledFunction()) {

                    /* function is not part of the API */
                    Graph Gprime(0);
                    
                    /* recursively calculate the AADG for it and integrate it onto G */
                    if (makeAbstractAPIDependenceGraph(*callee, Gprime, deep+1) > 0) {

                        /* copy all vertices from G' to G */
                        for (vertex_iterator ii=vertices(Gprime).first;
                                ii!=vertices(Gprime).second; ++ii) {

                            vertex_t v = vertex(*ii, Gprime),
                                     u = add_vertex(G);

                            G[u].uid   = Gprime[v].uid = uid++;
                            G[u].funID = Gprime[v].funID;
                            G[u].inst  = Gprime[v].inst;
                            G[u].bb    = Gprime[v].bb;
                            G[u].attr  = AADGNode::ATTR_NONE;
                        }

                        /* now copy all edges from G' to G */
                        for (edge_iterator ii=edges(Gprime).first; ii!=edges(Gprime).second; ++ii) {
                            vertex_t u = source(*ii, Gprime),
                                     v = target(*ii, Gprime);

                            add_edge(find(Gprime[u].uid, G), find(Gprime[v].uid, G), G);
                        }


                        /* create an auxiliary empty node that all leaves of G' point to it */
                        /* this gives G' a "diamond" shape */
                        vertex_t sink = add_vertex(G);

                        G[sink].uid   = uid++;
                        G[sink].funID = G[vertex(0, G)].funID;  // copy funID from another node  
                        G[sink].inst  = nullptr;
                        G[sink].attr  = AADGNode::ATTR_NONE;                        

                        /* complete the diamond by adding an edge from root and to all leaves */
                        for (vertex_iterator ii=vertices(Gprime).first;
                                ii!=vertices(Gprime).second; ++ii) {

                            vertex_t v = vertex(*ii, Gprime);


                            /* node has no incoming edges (= root) */
                            if (!in_degree(v, Gprime)) {
                                // add an edge from current node to the root of G'
                                add_edge(n, find(Gprime[v].uid, G), G);
                            }
                            
                            /* node has no outgoing edges (= leaf) */
                            if (!out_degree(v, Gprime)) {
                                // add an edge from the leaf of G' to the sink node of G
                                add_edge(find(Gprime[v].uid, G), sink, G);
                            }
                            

                            // Due to the removal of "empty" nodes, it is possible for root node
                            // to have incoming edges and for leaf nodes to have outgoing edges.
                            // To address this issues, we further use the node attributes.
                        
                            /* check if current node is the root */
                            if (Gprime[v].attr == AADGNode::ATTR_IS_ROOT) {
                                add_edge(n, find(Gprime[v].uid, G), G);
                            } 

                            /* or, check if current node is a leaf */
                            else if (Gprime[v].attr == AADGNode::ATTR_IS_LEAF) {
                                add_edge(find(Gprime[v].uid, G), sink, G);                            
                            }               
                        }


                        G[sink].bb = blk;           // sink should hold BB to allow further splits
                        G[n].bb    = nullptr;       // zero this to make find() to skip it

                        n = sink;                   // current node is sink


                        /* drop all nodes from G' to save memory */
                        for (vertex_iterator ii=vertices(Gprime).first;
                                ii!=vertices(Gprime).second;) {

                            remove_vertex(vertex(*ii, Gprime), Gprime);
                        }
                    }
                }
            }
        }


        /* look for adjacent BBs in CFG (essentially, slowly copy edges from CFG to AADG) */
        const TerminatorInst *ti = blk->getTerminator();

        /* get BB's terminator instruction and look for successor BBs */
        for (unsigned i=0; i<ti->getNumSuccessors(); ++i) {
            const BasicBlock *succ = ti->getSuccessor(i);

            /* "copy" the edge from CFG to AADG */
            add_edge(n, find(succ, G), G);

            if (visited.find(succ) != visited.end()) {
                continue;                           // skip visited nodes
            }

            visited[succ] = true;                   // mark node as visited
            Q.push(succ);                           // and add it to the queue
        }

        /* if basic block has no successors, mark it as a leaf */
        if (ti->getNumSuccessors() == 0) {
            G[find(blk, G)].attr = AADGNode::ATTR_IS_LEAF;
        }


        // at this point, BB points to the last node (after splits). However we should make
        // BB pointing back to the first node, because from now on any references to this
        // BB will only be backward edges.
        if (n != n_bkp) {                           // if n has moved
            G[n_bkp].bb = G[n].bb;                  // replace it back
            G[n].bb     = nullptr;
        }
    }



    // --------------------------------------------------------------------- //
    //                     * Drop empty nodes from AADG *                     //
    // --------------------------------------------------------------------- //

    /* iterate over vertices and fix edges from empty nodes */
    for (vertex_iterator ii=vertices(G).first; ii!=vertices(G).second; ++ii) {
        vertex_t v = vertex(*ii, G);


        if (G[v].inst) continue;                    // if node has already an instruction, skip it

        /* forward each incoming edge to all outgoing ones */
        for (out_edge_iterator out=out_edges(v, G).first; out!=out_edges(v, G).second; ++out) {
            for (in_edge_iterator in=in_edges(v, G).first; in!=in_edges(v, G).second; ++in) {

                /* add an edge to bypass current node */
                add_edge(source(*in, G), target(*out, G), G);
            }
        }


        /* when you drop a root, transfer the root attribute to its successors */
        for (out_edge_iterator out=out_edges(v, G).first; out!=out_edges(v, G).second; ++out) {
            // make sure that successor has no attributes assigned
            if (G[v].attr == AADGNode::ATTR_IS_ROOT && 
                    G[target(*out, G)].attr == AADGNode::ATTR_NONE) {

                G[target(*out, G)].attr = AADGNode::ATTR_IS_ROOT;
            }     
        }
        
        /* when you drop a leaf, transfer the leaf attribute to its predecessors */
        for (in_edge_iterator in=in_edges(v, G).first; in!=in_edges(v, G).second; ++in) {
            // make sure that predecessor has no attributes assigned
            if (G[v].attr == AADGNode::ATTR_IS_LEAF && 
                    G[source(*in, G)].attr == AADGNode::ATTR_NONE) {

                G[source(*in, G)].attr = AADGNode::ATTR_IS_LEAF;
            }              
        }
    
        /* clear all edges of the "empty" vertex */
        clear_out_edges(v, G);
        clear_in_edges(v, G);

        /* do not increment iterator, as the last element of the vector will fill the gap */
    }


    /* now drop all empty nodes */
    for (vertex_iterator ii=vertices(G).first; ii!=vertices(G).second; ) {
        vertex_t v = vertex(*ii, G);

        if (G[v].inst == nullptr) remove_vertex(v, G);
        else ++ii;
    }



    // --------------------------------------------------------------------- //
    //                    * Allocate interwork objects *                     //
    // --------------------------------------------------------------------- //
    for (vertex_iterator ii=vertices(G).first; ii!=vertices(G).second; ++ii) {
        vertex_t v = vertex(*ii, G);

  
        interwork::APICall *intlCall = findAPICall(G[v].inst->getCalledFunction()->getName());

        if (intlCall == nullptr) {
            G[v].APICall = new interwork::APICall(); // nullptr;    
        } else {
            G[v].APICall = intlCall->deepCopy();
        }       
    }


    // --------------------------------------------------------------------- //
    //                   * Print all vertices and edges *                    //
    // --------------------------------------------------------------------- //
    info(v2) << pad(deep) << "Printing vertices for '" << F.getName() << "' ...\n";

    for (vertex_iterator ii=vertices(G).first; ii!=vertices(G).second; ++ii) {
        vertex_t v = vertex(*ii, G);
 
        info(v2) << pad(deep) << "#" << v << " attr: " << G[v].attr << " ->" 
                 << *G[v].inst << " (" << G[v].funID << ") \n";
    }


    info(v2) << pad(deep) << "Printing edges for '" << F.getName() << "' ...\n";

    for (edge_iterator ii=edges(G).first; ii!=edges(G).second; ++ii) {
        info(v2) <<  pad(deep) <<"(" << source(*ii, G) << ", " << target(*ii, G) << ")\n";
    }


    info(v2) << pad(deep) << "* Exiting '" << F.getName() << "' *\n";

    AADGCallStack.erase(F.getName());               // drop function from the call stack


    return num_vertices(G);                         // return number of nodes left in AADG
}



// // ------------------------------------------------------------------------------------------------
// // Create the Dominator Tree for the generated Abstract API Dependence Graph.
// //
// vector<list<int>> Layout::makeDominatorTree(Graph &AADG) {
//     /* define a property map */
//     property_map_t idx = get(vertex_index, AADG);
//     
//     /* vector with dominator tree predecessors */
//     vector<vertex_t> DTreePredecessor = vector<vertex_t>(
//         num_vertices(AADG), graph_traits<Graph>::null_vertex()
//     );
// 
//     /* property iterator to go through vertices */
//     property_iterator DTreeIterator = make_iterator_property_map(DTreePredecessor.begin(), idx);
//     
//     /* vector of immediate dominators and final dominator tree (organized in layers) */
//     vector<int> iDominator(num_vertices(AADG));
//     vector<list<int>> domTree(num_vertices(AADG));
// 
//     info(v0) << "Building AADG's dominator tree...\n";
// 
// 
//     // --------------------------------------------------------------------- //
//     //                       * Build dominator tree  *                       //
//     // --------------------------------------------------------------------- //
// 
//     /* build the dominator tree using Lengauer-Tarjan algorithm */
//     lengauer_tarjan_dominator_tree(AADG, vertex(0, AADG), DTreeIterator);
// 
//     /* scan DTreeIterator to find the immediate dominators */
//     for (vertex_iterator ii=vertices(AADG).first; ii!=vertices(AADG).second; ++ii) {
// 
//         /* if vertex is in DTreeIterator, get its immediate dominator */
//         if (DTreeIterator[*ii] == graph_traits<Graph>::null_vertex()) {
//             iDominator[ idx[*ii] ] = -1;         // dominator does not exists
//         } else {
//             iDominator[ idx[*ii] ] = idx[ DTreeIterator[*ii] ];
//         }            
//     }
// 
//     info(v0) << "Done.\n";
//     
// 
//     /* build dominator tree from immediate dominators */
//     for (size_t i=0; i<iDominator.size(); ++i) {
//         info(v2) << "Immediate dominator of #" << i << ": " << iDominator[i] << "\n";
//         
//         /* domTree[i] contains a list with all children */               
//         if (iDominator[i] >= 0) {
//             domTree[ iDominator[i] ].push_back(i);
//         }
//     }
// 
// 
//     // --------------------------------------------------------------------- //
//     //                       * Print dominator tree  *                       //
//     // --------------------------------------------------------------------- //
// 
//     info(v1) << "Dominator Tree:\n";
// 
//     for (size_t i=0; i<domTree.size(); ++i) {
//         string children = "";                    // node's children
// 
//         /* concatenate all children for current node */
//         for (auto ii=domTree[i].begin(); ii!=domTree[i].end(); ++ii) {
//             children = children + to_string(*ii) + " ";
//         }
// 
//         info(v1) << "    " << i << "  ->  " << children << "\n";
//     }
// 
// 
//     return domTree;                              // return Dominator Tree
// }
// 
// 
// 
// // ------------------------------------------------------------------------------------------------
// // Dump Dominator Tree nodes into pools. The idea here, is to place all nodes at depth i into the
// // i-th pool.
// //
// adjacency_list_t Layout::makePools(adjacency_list_t &domTree) {
// 
// #define LAYER_DELIMITER -2                       // needs to be a negative number
// 
//     adjacency_list_t pool(domTree.size());       // in the worst case we'll have 1 pool per node
//     std::queue<int>  Q;                          // queue for BFS
//     map<int, bool>   visited;                    // visited nodes
//     int              currpool = 0;               // current pool to place nodes       
// 
// 
//     info(v0) << "Dumping Dominator Tree nodes into pools...\n";   
// 
//     // One challenge here is to find the depth of the front node in the queue. One solution is
//     // to store pairs (node, depth) in the queue instead of nodes. However we'll do something
//     // simpler: Due to the BFS algorithm, if we scan the queue from left to right, we'll see that
//     // node depths are in non-decreasing order. We can exploit this fact by adding delimiters
//     // (delimiter: some negative number) every time that a node has higher depth than its previous.
//     // Thus, every time that the front element of the queue is a delimiter, we can switch to a
//     // new pool.
// 
//     Q.push(0);                                   // add the root
//     Q.push(LAYER_DELIMITER);                     //   and the delimiter on the queue
//     visited[0] = true;                           // mark root as visited
// 
//     
//     while (!Q.empty()) {                         // classic BFS
//         int top = Q.front();                     // get front element and
//         Q.pop();                                 // pop it from queue
//      
//         if (top == LAYER_DELIMITER) {            // if we hit a delimiter
//             /* when queue gets empty, stop adding delimiters and exit */
//             if (Q.empty()) break;
//             
//             /* a delimiter indicates that the front node in the next iteration will be
//              * 1 layer deeper in the dominator tree. This implies that we have already
//              * done with processing nodes at current depth j, so due to BFS, at this 
//              * point queue contains all nodes at depth j+1 only. Hence we can add a new
//              * delimiter to the queue.
//              */
//             Q.push(LAYER_DELIMITER);             // add a new delimiter at the back of the queue
//             ++currpool;                          // move on the next pool
// 
//             continue;            
//         }
//     
//         pool[currpool].push_back(top);           // place node to the right pool
// 
//         /* add neighbors to the queue */
//         for (auto ii=domTree[top].begin(); ii!=domTree[top].end(); ++ii) {    
//             if (visited.find(*ii) != visited.end()) {
//                 continue;                        // skip visited nodes
//             }
// 
//             visited[*ii] = true;                 // mark node as visited
//             Q.push(*ii);                         // and add it to the queue
//         }
//     }
// 
//     info(v0) << "Done.\n";
// 
// 
//     // --------------------------------------------------------------------- //
//     //                           * Print pools  *                            //
//     // --------------------------------------------------------------------- //
//     info(v1) << "Printing pools...\n";
// 
//     for (int i=0; i<currpool; ++i) {
//         string nodes = "";
// 
//         for (auto ii=pool[i].begin(); ii!=pool[i].end(); ++ii) {
//             nodes = nodes + to_string(*ii) + " ";
//         }
// 
//         info(v1) << "   pool #" << i << " contains nodes: " << nodes << "\n";
//     }
// 
// 
//     return pool;                                 // return function pools
// 
// #undef LAYER_DELIMITER
// }



// ------------------------------------------------------------------------------------------------
// Visitor class that is being used as a callback upon DFS.
//
class DFSVisitor : public dfs_visitor<> {
public:
    /* class constructor */
    DFSVisitor(map<pair<int, int>, bool> &bwEdges) : bwEdges(bwEdges) { }

    /* callback that is invoked when a backward edge is encountered */
    template <class Edge, class Graph>
    void back_edge(Edge e, Graph &AADG) {
        /* save the backward edge for later */
        bwEdges[make_pair(source(e, AADG), target(e, AADG))] = true;
    }


private:
    map<pair<int, int>, bool> &bwEdges;             // map with backward edges
};



// ------------------------------------------------------------------------------------------------
// Given the AADG, generate function pools. The process is as follows: First we drop all backward
// edges from AADG to ensure that it's acyclic (our final fuzzer needs to be flat as well). Then we
// we perform a topological sorting.
//
adjacency_list_t Layout::makePools(Graph &AADG) {
    adjacency_list_t pool(num_vertices(AADG));      // in the worst case we'll have 1 pool per node
    int              currpool = 0;                  // current pool to place nodes       

    iPools.clear();                                 // clear reverse index as well (!)


    /* clear ignore attributes first */
    for (vertex_iterator ii=vertices(AADG).first; ii!=vertices(AADG).second; ++ii) {
        vertex_t v = vertex(*ii, AADG);

        AADG[v].attr &= ~AADGNode::ATTR_IGNORE;
    }


    // --------------------------------------------------------------------- //
    //                          * Generate Pools *                           //
    // --------------------------------------------------------------------- //
    info(v0) << "Generating function pools...\n";   
 
    // We use a modified version of Kahn's topological sorting algorithm to find out
    // how to place vertices into pools. At each step we extract all vertices with no
    // incoming edges and we place them into the same pool. Then we remove those vertices
    // (along with their edges) and we repeat, until AADG becomes empty.
    //
    // The problem here is that this requires to modify the AADG. Hence, instead of
    // removing a vertex we give him the "ignore" attribute, so it is excluded from the
    // search. Also we exclude backward edges from search as thoses edges make the AADG
    // cyclic and therefore we cannot apply our topological sorting algorithm.
    //
    // Complexity here is quadratic, but honestly, I don't care.
    for (;;) {
        /* count the number of nodes that are not "ignored" */
        unsigned ignNodes = 0;

        for (vertex_iterator ii=vertices(AADG).first; ii!=vertices(AADG).second; ++ii) {
            vertex_t v = vertex(*ii, AADG);

            if (AADG[v].attr & AADGNode::ATTR_IGNORE) {
                ++ignNodes;
            }
        }

        info(v2) << "Initializing pool #" << currpool << " ...\n";
        info(v2) << "IGNORE " << ignNodes << "\n";

        /* if all nodes are "ignored" then stop */
        if (ignNodes == num_vertices(AADG)) {
            break;
        } 
      

        /* iterate over vertices and place into current pool those without incoming edges (roots) */
        for (vertex_iterator ii=vertices(AADG).first; ii!=vertices(AADG).second; ++ii) {
            vertex_t v      = vertex(*ii, AADG);
            bool     isRoot = true;


            if (AADG[v].attr & AADGNode::ATTR_IGNORE) {
                continue;                           // skip nodes that are marked as "ignored"
            }

            /* iterate over incoming edges */
            for (in_edge_iterator in=in_edges(v, AADG).first; in!=in_edges(v, AADG).second; ++in) {
                vertex_t u = source(*in, AADG);

                if (isBackwardEdge(u, v)) {
                    continue;                       // skip backward edges (o/w AADG is not acyclic)
                }

                if (AADG[u].attr & AADGNode::ATTR_IGNORE) {
                    continue;                       // skip nodes that are marked as "ignored"
                }

                isRoot = false;
                break;                              // 1 incoming edge is enough     
            }

            /* if no incoming edges found, node is a root */
            if (isRoot) {
                if (AADG[v].APICall) {
                    pool[currpool].push_back(v);        // place node to the right pool

                    iPools[v] = currpool;               // associate the inverse pool as well
                } 

                // If APICall object is empty, ignore that node to avoid infinity loops.
                // TODO: That's a quick fix. Do something better.
                else {
                    AADG[v].attr |= AADGNode::ATTR_IGNORE;
                }
            }    
        }

        if (pool[currpool].size() > 0) {
            /* now mark all root vertices as "ignored" and go back */
            for (auto jj=pool[currpool].begin(); jj!=pool[currpool].end(); ++jj) {
                AADG[*jj].attr |= AADGNode::ATTR_IGNORE;
            }
        }

        ++currpool;                                 // move on the next pool
    }


    info(v0) << "Done.\n";


    // --------------------------------------------------------------------- //
    //                           * Print pools  *                            //
    // --------------------------------------------------------------------- //
    info(v1) << "Printing pools...\n";

    for (int i=0; i<currpool; ++i) {
        string nodes = "";

        for (auto ii=pool[i].begin(); ii!=pool[i].end(); ++ii) {
            nodes = nodes + to_string(*ii) + " ";
        }

        info(v1) << "   pool #" << i << " contains node(s): " << nodes << "\n";
    }


    return pool;                                    // return function pools

}



// ------------------------------------------------------------------------------------------------
// Check whether an AADG edge is a backward edge.
//
bool Layout::isBackwardEdge(vertex_t from, vertex_t to) {
    return backEdges.find(make_pair(from, to)) != backEdges.end();
}



// ------------------------------------------------------------------------------------------------
// Check whether there's a path in CFG between 2 AADG vertices.
//
bool Layout::isCFGReachable(vertex_t from, vertex_t to) {
    std::stack<const BasicBlock *> S;
    map<const BasicBlock *, bool>  visited;

    const BasicBlock *start = AADG[from].inst->getParent();
    const BasicBlock *end   = AADG[to].inst->getParent();


    /* check whether both instructions belong in the same basic block */
    if (start == end) {
        /* if "inst" dominates "entry" then it's in the slice (as both are in the same block) */
        return CFG_domTree->dominates(AADG[from].inst, AADG[to].inst);
    }
       

    S.push(start);                                  // from call in stack
    visited[start] = true;

    /* DFS on CFG */
    while (!S.empty()) {
        const BasicBlock *curr = S.top();           // get top of the stack
        S.pop();

     
        if (curr == end) {                          // basic block found
            return true;
        }

        /* traverse CFG backwards (follow predecessors) */
        for (const BasicBlock *Succ : successors(curr)) {            
            if (visited.find(Succ) != visited.end()) {
                continue;                           // skip visited nodes
            }

            visited[Succ] = true;                   // mark as visited
            S.push(Succ);                           // and push it on the stack


            /* check for call instructions and continue search inside caller */
            for (auto ii=Succ->begin(); ii!=Succ->end(); ++ii) {
                
                /* we only care about call instructions */
                if (const CallInst *call = dyn_cast<CallInst>(ii)) {
                
                    /* make sure taht callee exists and has >0 basic blocks */
                    if (call->getCalledFunction() && !call->getCalledFunction()->isDeclaration()) {                    
                        const BasicBlock *entry = &call->getCalledFunction()->getEntryBlock();

    
                        if (visited.find(entry) == visited.end()) {
                            visited[entry] = true;
                            S.push(entry);

                        }
                    }
                }
            }
        }
    }   

    return false;                                   // no path found
}



// ------------------------------------------------------------------------------------------------
// Visualize the Abstract API Dependence Graph. This function expresses AADG into DOT format and
// saves it into a *.dot file, so it can be visualized later through 'dot' command: 
//      "dot -Tpdf AADG.dot -o AADG.pdf"
//
// Please note that we cannot use the boost's built-in function "write_graphviz()", as it requires
// the use of RTTI, but FuzzGen is compiled with the -fno-rtti flag.
//
bool Layout::visualizeAADG(const string filename) {
    ofstream           ofs(filename + ".dot");      // create a .dot file
    string             tmp_output;                  //
    raw_string_ostream dot(tmp_output);             // use this to print StringRefs


    info(v0) << "Visualizing AADG...\n";

    if (!ofs) {
        fatal() << "Cannot create DOT file '" << filename << "'.\n";
        return false;                               // failure
    }


    /* write header*/
    ofs << "digraph Abstract_API_Dependence_Graph {" << "\n";
  
    /* write vertices first */
    for (vertex_iterator ii=vertices(AADG).first; ii!=vertices(AADG).second; ++ii) {
        vertex_t v = vertex(*ii, AADG);


        if (AADG[v].inst == nullptr) {
            throw FuzzGenException("visualizeAADG(): NULL vertex in AADG");
        }


        const Function *callee = AADG[v].inst->getCalledFunction();
        string         type    = "";


        if (AADG[v].inst->getNumOperands() > 1) {
            // In libhevc/libavc cases, there's a single API call, so we also print the
            // type of the 2nd argument to distinguish the calls (DEBUG ONLY).
            if (const BitCastInst *bc = dyn_cast<BitCastInst>(AADG[v].inst->getOperand(1))) {
                type = "\\n" + Dig::getTypeStr(bc->getSrcTy());
            }
        }
 
        string color = "white";

        if (AADG[v].attr & AADGNode::ATTR_COMMON) {
            color = "greenyellow";
        } else if (AADG[v].attr & AADGNode::ATTR_NEW) {
            color = "gray";
        }

         dot << v << "\t[shape=box; style=filled; fillcolor=" << color << "; "
             << "label=\"#" << v << ":" << AADG[v].funID << " "
             << AADG[v].inst->getFunction()->getName() 
             << "\\n" << callee->getName() << type
             << "\"];" << "\n";
    }

    
    /* then write edges */
    for (edge_iterator ii=edges(AADG).first; ii!=edges(AADG).second; ++ii) {
        vertex_t from = source(*ii, AADG),
                 to   = target(*ii, AADG);
        
        dot << from << " -> " << to;

        /* if edge is a backward edge use a different color */ 
        if (backEdges.find(make_pair(from, to)) != backEdges.end()) {
            dot << " [color=blue]";
        } 
        
        dot << "; \n";
    }


    /* dump everything to the file */
    ofs << dot.str() << "\n";  
    ofs << "}" << "\n";
    ofs.close();

    info(v0) << "file created successfully as '" << filename << ".dot'\n";
    
    return true;
}



// // ------------------------------------------------------------------------------------------------
// // Visualize the Dominator Tree. This function is similar to visualizeAADG().
// //
// bool Layout::visualizeDomTree(const string filename) {
//     ofstream           ofs(filename + ".dot");   // create a .dot file
//     string             tmp_output;               //
//     raw_string_ostream dot(tmp_output);          // use this to print StringRefs
// 
// 
//     info(v0) << "Visualizing Dominator Tree...\n";
// 
//     if (!ofs) {
//         fatal() << "Cannot create DOT file.\n";
//         return false;                            // failure
//     }
// 
//     /* write tree header */
//     ofs << "digraph Dominator_Tree {" << "\n";
//   
// 
//     // --------------------------------------------------------------------- //
//     //                     * Visualize Dominator Tree  *                     //
//     // --------------------------------------------------------------------- //
//     for (size_t v=0; v<domTree.size(); ++v) {   // write nodes
//         const Function *callee = AADG[v].inst->getCalledFunction();
//         string         type    = "";
// 
// 
//         // In libhevc/libavc cases, there's a single API call, so we also print the
//         // type of the 2nd argument to distinguish the calls (DEBUG ONLY).
//         if (const BitCastInst *bc = dyn_cast<BitCastInst>(AADG[v].inst->getOperand(1))) {
//             type = "\\n" + Dig::getTypeStr(bc->getSrcTy());
//         }
// 
// 
//         dot << v << "\t[shape=box; label=\"#" << v << ": "
//             << AADG[v].inst->getFunction()->getName() 
//             // << "\\n" << *AADG[v].inst << "\"];" << "\n";
//             << "\\n" << callee->getName() << type
//             << "\"];" << "\n";
//     }
// 
//     for (size_t i=0; i<domTree.size(); ++i) {   // write edges
//         for (auto ii=domTree[i].begin(); ii!=domTree[i].end(); ++ii) {
//             dot << i << " -> " << *ii << "; \n";
//         }       
//     }
// 
// 
//     // --------------------------------------------------------------------- //
//     //                   * Visualize pools as clusters  *                    //
//     // --------------------------------------------------------------------- //
//     for (size_t i=0; i<pools.size(); ++i) {
//         
//         /* draw a rectangle to group all nodes of the same pool */
//         dot << "subgraph cluster_" << i << " {" << "\n";
// 
//         for (auto ii=pools[i].begin(); ii!=pools[i].end(); ++ii) {
//             dot << *ii << "; \n";
//         }       
// 
//         dot << "label = \"pool #" << i << "\"" 
//             << "color=purple; fontcolor=purple; labeljust=l" << "\n" 
//             << "}" << "\n";
//     }
// 
// 
//     /* dump everything to the file */
//     ofs << dot.str() << "\n";  
//     ofs << "}" << "\n";
//     ofs.close();
// 
//     info(v0) << "file successfully created.\n";
//     
//     return true;
// }



// ------------------------------------------------------------------------------------------------
// Return the root node of AADG (we ignore backward edges). According to AADG construction this
// node must be unique.
//
vertex_t Layout::AADGroot(void) {

    /* iterate over vertices and get select the one with no incoming edges */
    for (vertex_iterator ii=vertices(AADG).first; ii!=vertices(AADG).second; ++ii) {
        vertex_t v      = vertex(*ii, AADG);
        bool     isRoot = true;

        /* iterate over incoming edges */
        for (in_edge_iterator in=in_edges(v, AADG).first; in!=in_edges(v, AADG).second; ++in) {
            vertex_t u = source(*in, AADG);

            if (isBackwardEdge(u, v)) {
                continue;                       // skip backward edges (o/w AADG is not acyclic)
            }

            isRoot = false;
            break;                              // 1 incoming edge is enough     
        }

        /* if no incoming edges found, node is a root */
        if (isRoot) {
            info(v2) << "Root node of AADG is #" << v << "\n";
            return v;
        }    
    }

    /* ok something went wrong here */
    throw FuzzGenException("AADGroot(): Cannot find root node in AADG");
}    



// ------------------------------------------------------------------------------------------------
// Return the total number of nodes in AADG.
//
unsigned Layout::AADGsize(void) {
    return num_vertices(AADG);
}    



// ------------------------------------------------------------------------------------------------
// Return the total number of edges in AADG.
//
unsigned Layout::AADGedges(void) {
    return num_edges(AADG);
}



// ------------------------------------------------------------------------------------------------
// Find backward edges in AADG.
//
void Layout::findBackEdges(void) {
    info(v2) << "Looking for backward edges in AADG...\n";
    
    backEdges.clear();

    DFSVisitor V(backEdges);
    depth_first_search(AADG, visitor(V));           // do a DFS looking for backward edges

    /* then write edges */
    for (edge_iterator ii=edges(AADG).first; ii!=edges(AADG).second; ++ii) {
        vertex_t u = source(*ii, AADG),
                 v = target(*ii, AADG);

        if (backEdges.find(make_pair(u,v)) != backEdges.end()) {
            info(v2) << "AADG edge (" << u << ", " << v << ") is backward\n";
        }
    }
}    



// ------------------------------------------------------------------------------------------------
// Delete a node from AADG. To make sure that AADG won't be disconnected, properly forward edges
// from deleted node. 
//
bool Layout::deleteNode(vertex_t v) {

    // --------------------------------------------------------------------- //
    //      * Ensure that AADG will have a unique root after deletion *      //
    // --------------------------------------------------------------------- // 
    if (v == AADGroot()) {
        /* if we delete the root, we should make sure that AADG still has a unique root */
        int ctr = 0;

        /* count incoming edges */
        for (out_edge_iterator out=out_edges(v, AADG).first; out!=out_edges(v, AADG).second;
                ++out) {

            // a root cannot have outgoing backward edges
            ++ctr;            
        }

        /* if root has >1 children we have a problem */
        if (ctr > 1) {
            warning() << "Cannot delete vertex '" << v << "' from AADG\n";

            return false;                           // deletion not possible
        }
    }


    // --------------------------------------------------------------------- //
    //                       * Delete node from AADG *                       //
    // --------------------------------------------------------------------- //
    /* forward each incoming edge to all outgoing ones */
    for (out_edge_iterator out=out_edges(v, AADG).first; out!=out_edges(v, AADG).second; ++out) {
        for (in_edge_iterator in=in_edges(v, AADG).first; in!=in_edges(v, AADG).second; ++in) {

            /* add an edge to bypass current node */
            add_edge(source(*in, AADG), target(*out, AADG), AADG);
        }
    }


    info(v2) << "Deleting vertex '" << v << "' from AADG\n";

    /* clear all edges of the and the vertex */
    clear_out_edges(v, AADG);
    clear_in_edges(v, AADG);
    remove_vertex(v, AADG);

    return true;                                    // deletion was successful
}



// ------------------------------------------------------------------------------------------------
// Create the fuzzer layout for the API Calls.
//
bool Layout::makeAPICallLayout(const Function &func) {
    info(v0) << "Creating the API call layout starting from '" << func.getName() << "'...\n";


    /* create the AADG starting from the root function */
    AADGCallStack.clear();                          // clear call stack

    makeAbstractAPIDependenceGraph(func, AADG, 0);
    // domTree = makeDominatorTree(AADG);
    // pools   = makePools(domTree);


    /* find backward edges */
    findBackEdges();

    /* generate pools from the acyclic AADG */
    pools = makePools(AADG);


    /* check if AADG is empty */
    if (num_vertices(AADG) < 1) {
        warning() << "AADG is empty!\n";
        return false;                               // failure
    }


    info(v0) << "Layout created successfully.\n";

    return true;                                    // success!
}



// ------------------------------------------------------------------------------------------------
// Update the fuzzer layout for the API Calls (after AADG is coalesced)
//
void Layout::updateAPICallLayout() {
    info(v0) << "Updating the API call layout...\n";

    /* find backward edges */
    findBackEdges();
    
    /* generate pools from the acyclic AADG */
    pools = makePools(AADG);


    info(v0) << "Layout updated successfully.\n";
}

// ------------------------------------------------------------------------------------------------
