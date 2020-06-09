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
 * coalesce.cpp
 *
 * TODO: Write a small description.
 *
 */
// ------------------------------------------------------------------------------------------------
#include "coalesce.h"



// ------------------------------------------------------------------------------------------------
// Class constructor.
//
Coalesce::Coalesce(Context * ctx) : ctx(ctx) {

    info(v0) << "Coalesce module started.\n";
}



// ------------------------------------------------------------------------------------------------
// Generate a unique hash based on the AADG node, to ease comparison
//
string Coalesce::vertexHash(AADGNode &node) {

    if (node.APICall == nullptr) {
        throw FuzzGenException("vertexHash(): Hash on NULL APICall object");
    }

    return node.APICall->hash();
}



// ------------------------------------------------------------------------------------------------
// If 2 AADGs have at least one common node, return true.
//
bool Coalesce::haveCommonNode(Graph &AADG1, Graph &AADG2) {
    map<string, bool> nodeHash;

    /* collect node hashes for the 1st AADG */
    for (vertex_iterator ii=vertices(AADG1).first; ii!=vertices(AADG1).second; ++ii) {
        vertex_t v = vertex(*ii, AADG1);
       

        if (AADG1[v].APICall) {
            nodeHash[ vertexHash(AADG1[v]) ] = true;
        }
    }


    /* check if the hash for each node in 2nd AADG in the list (linear search time amortized) */
    for (vertex_iterator jj=vertices(AADG2).first; jj!=vertices(AADG2).second; ++jj) {
        vertex_t v = vertex(*jj, AADG1);       

        if (AADG2[v].APICall) {
            if (nodeHash.find(vertexHash(AADG2[v])) != nodeHash.end()) {
                info(v2) << "Node " << v << " is common. Hash: " << vertexHash(AADG2[v]) << "\n";

                return true;
            }
        }
    }

    return false;
}



// ------------------------------------------------------------------------------------------------
// Find the first node that is common (if exists) in AADG. Note that there can be many common
// nodes. We just select 1.
//
vertex_t Coalesce::findFirstCommon(Graph &AADG, AADGNode *node) {
    if (!node->APICall) {
        return INVALID_VERTEX;
    }


    string hash = vertexHash(*node);

    /* iterate over AADG vertices */
    for (vertex_iterator ii=vertices(AADG).first; ii!=vertices(AADG).second; ++ii) {
        vertex_t v = vertex(*ii, AADG);
       
        if (AADG[v].APICall == nullptr) {
            continue;
        }

        /* We ignore nodes that are come from the 2nd AADG (NEW attribute) */
        if (AADG[v].attr & AADGNode::ATTR_NEW || AADG[v].attr & AADGNode::ATTR_COMMON) {
            continue;
        }

        /* check whether hashes match */
        if (hash == vertexHash(AADG[v])) {
            return v;                               // vertex found!
        }
    }

    return INVALID_VERTEX;                          // vertex not found
}



// ------------------------------------------------------------------------------------------------
// Merge the non-common parts of the node.
//
bool Coalesce::mergeArguments(interwork::Argument *a1, interwork::Argument *a2) {

    /* we assume that all checks have already passed, so we only merge the other fields */

    if (a1->subElements.size() != a2->subElements.size()) {
        throw FuzzGenException("mergeArguments(): Sub-elements do not have the same size");
    }


    /* merge attributes first (as you do in backward slicing) */
    a1->attr = Backward::mergeAttributes(a1->attr, a2->attr);

    if ((a1->attr->flags & ATTR_FUNCPTR) && !a1->funcptr) {
        a1->funcptr = a2->funcptr;                  // use just 1 function pointer
    }


    // 'hasfakedep' and 'parent' are not needed anymore so we ignore them

    /*
     * If both arguments do not define a dependency, we can simply merge their attributes.
     * Otherwise, each argument generates a different final value. In that case we have
     * to select at runtime which one to use, so we keep both arguments.
     * 
     * For example if each argument uses a different dependency, we select at runtime which
     * dependency to use in the function.
     */
    if (a1->depTy == Dep_none && a2->depTy == Dep_none) {
        /* no action */
    } else {
        a1->switchArgs.push_back(a2);               // add argument to "switch" argumments
    }


    /* recursively merge each subelement */
    for(auto ii=a1->subElements.begin(),  jj=a2->subElements.begin();
             ii!=a1->subElements.end() && jj!=a1->subElements.end(); ++ii, ++jj) {

        mergeArguments(*ii, *jj);
    }


    /* transfer swithArgs from the other argument */
    for (size_t j=0; j<a2->switchArgs.size(); ++j) {
        a1->switchArgs.push_back(a2->switchArgs[j]); 
    }


    return false;
}



// ------------------------------------------------------------------------------------------------
// Merge the non-common parts of an AADG node
//
bool Coalesce::mergeVertex(AADGNode &n1, AADGNode &n2) {
    info(v0) << "Merging Vertex '" << n1.APICall->name << "' ...\n";


    /* base checks */
    if (n1.APICall->name        != n2.APICall->name || 
        n1.APICall->args.size() != n2.APICall->args.size()) {
            throw FuzzGenException("mergeVertex(): Node cannot be merged");
    }


    /* merge dependencies on return values */
    if (n2.APICall->depTy == interwork::Dep_def) {

        if (n1.APICall->depTy != interwork::Dep_def) {
            n1.APICall->depTy = n2.APICall->depTy;
            n1.APICall->depID = n2.APICall->depID;

        } else {
            /* we have multiple dependence definitions, so create assignments later on */
            n1.APICall->depAsg.push_back(n2.APICall->depID);
        }
    }


    /* merge each argument */
    for (size_t i=0; i<n1.APICall->args.size(); ++i) {
        mergeArguments(n1.APICall->args[i], n2.APICall->args[i]);
    }


    /* TODO: Merge hasFailure, val, op, APICall->vals, APICall->ops */


    return true;
}



// ------------------------------------------------------------------------------------------------
// Coalesce 2 AADGs into a single one.
//
bool Coalesce::coalesce(Graph &AADG1, Graph &AADG2) {
    map<vertex_t, vertex_t> V;
    int  attr;
    bool stopMerging = false;


    /* copy all non-common vertices from AADG2 to AADG1 */
    for (vertex_iterator ii=vertices(AADG2).first; ii!=vertices(AADG2).second; ++ii) {
        vertex_t v = vertex(*ii, AADG2),
                 u = findFirstCommon(AADG1, &AADG2[v]);


        /* is node v common? */
        if (stopMerging || u == INVALID_VERTEX) {   // not common. Add a new vertex
             u    = add_vertex(AADG1);
             attr = AADGNode::ATTR_NEW;

        } else {                                    // common. simply merge vertices
            attr = AADGNode::ATTR_COMMON;

            info(v2) << "Merging vertices " << v << " and " << u << "\n";

            mergeVertex(AADG2[v], AADG1[u]);

            /* don't blindly merge multiple many nodes you'll screw up the dependencies */
            stopMerging = true;                     // merge only 1 node
        }

        V[v] = u;                                   // associate vertices between AADG1 and AADG2

        AADG1[u] = AADG2[v];                        // initialize new node 
        AADG1[u].attr |= attr;                      // update attributes

        // Don't delete AADG2, as AADG1 uses objects from it
    }


    /* finally, copy all edges from G' to G */
    for(edge_iterator ii=edges(AADG2).first; ii!=edges(AADG2).second; ++ii) {
        vertex_t u = source(*ii, AADG2),
                 v = target(*ii, AADG2);

        add_edge(V[u], V[v], AADG1);
    }    


    return true;
}

// ------------------------------------------------------------------------------------------------
