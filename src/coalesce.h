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
 * coalesce.h
 *
 * Header file for coalesce.cpp.
 *
 */
// ------------------------------------------------------------------------------------------------
#ifndef LIBRARY_COALESCE_H

#include "common.h"
#include "interwork.h"
#include "layout.h"
#include "backward.h"

#include <sstream>
#include <string>
#include <map>

#include <boost/graph/graph_traits.hpp>             // boost libraries
#include <boost/graph/adjacency_list.hpp>
#include <boost/property_map/property_map.hpp>
#include <boost/graph/dominator_tree.hpp>
#include <boost/graph/copy.hpp>

#define INVALID_VERTEX 0xffff

using namespace std;
using namespace boost;
using namespace interwork;



// ------------------------------------------------------------------------------------------------
// * Coalesce module *
//
// This moduels coalesces 2 AADGs together.
//
class Coalesce {
public:
    /* class constructor */
    Coalesce(Context *);

    /* coalesce 2 AADGs */
    bool coalesce(Graph &, Graph &);
   
    /* get the hash of a vertex */
    string vertexHash(AADGNode &);

    /* check if 2 AADGs have at least a common node */
    bool haveCommonNode(Graph &, Graph &);

private:
    Context *ctx;                                   // execution context


    /* find the first common node in an AADG */
    vertex_t findFirstCommon(Graph &, AADGNode *);

    /* merge 2 arguments together */
    bool mergeArguments(interwork::Argument *, interwork::Argument *);

    /* merge 2 vertices together*/
    bool mergeVertex(AADGNode &, AADGNode &);
};

// ------------------------------------------------------------------------------------------------
#endif
