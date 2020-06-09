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
 * FuzzGen - The Automatic Fuzzer Generator
 *
 *
 *
 * blkcov.cpp
 *
 * This program is part of FuzzGen evaluation. It runs under DynamoRIO dynamic binary
 * instrumentation framework and counts the distinct basic blocks that are being executed
 * for each module.
 *
 * To compile this source file, place it under "$DYNAMORIO_HOME/api/samples" directory and add
 *  the following line to "$DYNAMORIO_HOME/api/samples/CMakeLists.txt": 
 *
 *      `add_sample_client(blkcov "blkcov.cpp"  "drmgr;drreg;drx")`
 *
 * Then go to the build directory, "make" and run it `bin64/drrun -c ./api/bin/libblkcov.so -- ls`
 *
 */
// ------------------------------------------------------------------------------------------------
#include "dr_api.h"
#include "drmgr.h"
#include "dr_tools.h"
#include "droption.h"

#include <stdio.h>                                  // C includes
#include <stdlib.h>
#include <string.h>

#include <string>                                   // C++ STL includes
#include <vector>
#include <set>
#include <map>


/* uncomment the MACRO to display verbose information */
// #define __DEBUG__


using namespace std;



// ------------------------------------------------------------------------------------------------
// Global variables.
//
static map<string, set<app_pc>> covered_blks;       // covered basic blocks for each module
static void                     *stats_mutex;       // mutex to safely print in multithread env.
static long int                 blk_count;          // total number of basic blocks executed

/* command line option(s) */
static droption_t<string> outfile(
    DROPTION_SCOPE_CLIENT, 
    "outfile", 
    "blocks.cov",                                   // default filename
    "Output filename to hold coverage information",
    "Output filename to hold coverage information");



// ------------------------------------------------------------------------------------------------
// Callback invoked each time that a new basic block is about to execute.
//
static dr_emit_flags_t event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb,
                                         bool for_trace, bool translating, OUT void **user_data) {
    
    instr_t *instr;                                 // hold 1st instruction of bb


    if (translating) {
        return DR_EMIT_DEFAULT;
    }


    /* get the 1st instruction from basic block */
    if ((instr = instrlist_first_app(bb))) {
        app_pc        address = instr_get_app_pc(instr);
        module_data_t *module = dr_lookup_module(address);

        if (!module) {
            dr_mutex_lock(stats_mutex);
            dr_printf("[!] Error. Cannot get module for block at 0x%016llx\n", address);
            dr_mutex_unlock(stats_mutex);        
    
            return DR_EMIT_DEFAULT;
        }

        /* get module name */
        string mod_name = dr_module_preferred_name(module);

        /* add module to the hashmap */
        covered_blks[mod_name].insert(address);


#ifdef __DEBUG__    
        dr_mutex_lock(stats_mutex);
        dr_printf("%6d Hit block 0x%016llx (%s)\n", ++blk_count, address, mod_name.c_str());
        dr_mutex_unlock(stats_mutex);        
#endif
    }

    return DR_EMIT_DEFAULT;
}



// ------------------------------------------------------------------------------------------------
// Callback invoked after all processing is done.
//
static void event_exit() {
    map<string, set<app_pc>>::iterator ii;          // iterators
    set<app_pc>::iterator jj;    
    size_t total = 0;                               // total number of distinct basic blocks


    /* print results */
    dr_printf("[+] Instrumentation finished. %ld blocks executed.\n", blk_count);
    dr_printf("[+]    +----------------------------------+----------+\n");    
    dr_printf("[+]    |           Module Name            |  Blocks  |\n");
    dr_printf("[+]    +----------------------------------+----------+\n");
        
    for (ii=covered_blks.begin(); ii!=covered_blks.end(); ++ii) {
        dr_printf("[+]    | %-32s | %8zu |\n", ii->first.c_str(), ii->second.size());

        total += ii->second.size();
    }

    dr_printf("[+]    +----------------------------------+----------+\n");    
    dr_printf("[+]    | Total                            | %8zu |\n", total);
    dr_printf("[+]    +----------------------------------+----------+\n");
    dr_printf("[+]\n");


    /* store results to a file for later processing */
    file_t file = dr_open_file(outfile.get_value().c_str(), DR_FILE_WRITE_OVERWRITE);

    if (file == INVALID_FILE) {
        dr_printf("[!] Error. Cannot create file.\n");
    } else {
        for (ii=covered_blks.begin(); ii!=covered_blks.end(); ++ii) {
            dr_fprintf(file, "@module\t%s\t%zu\n", ii->first.c_str(), ii->second.size());

            for (jj=ii->second.begin(); jj!=ii->second.end(); ++jj) {
                dr_fprintf(file, "@blkid\t%s\t0x%016llx\n", ii->first.c_str(), *jj);
            }

            dr_fprintf(file, "\n");
        }

        dr_close_file(file);
    }

    // The following code prints the current memory map:
    //
    //     char   buf[512];
    //     file_t file = dr_open_file("/proc/self/maps", DR_FILE_READ);
    //   
    //     dr_printf("\n\nMemory map:\n");
    // 
    //     for (;;) {
    //         memset(buf, 0, 512);
    //         if (dr_read_file(file, buf, 500) < 1) {
    //             break;
    //         }
    // 
    //         dr_printf("%s", buf);
    //     }
    // 
    //     dr_printf("\n\n\n");
    //     dr_close_file(file);
    //

    
    dr_printf("[+] Instrumentation has finished. Results are stored to '%s'.\n", 
            outfile.get_value().c_str());
    dr_printf("[+] Bye bye :)\n");


    dr_mutex_destroy(stats_mutex);
    drmgr_exit();
}



// ------------------------------------------------------------------------------------------------
// intrumentation's main() function. Analysis starts from here.
//
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    dr_set_client_name("FuzzGen Evaluation: Block Coverage", "https://ispo.gr");

    /* parse command line options */
    if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, NULL, NULL)) {
        dr_printf("[!] Error. Please check again command line arguments.\n");

        DR_ASSERT(false);
    }

    
    /* initialize globals */
    stats_mutex = dr_mutex_create();
    blk_count   = 0;

    /* register event callbacks */
    drmgr_init();
    drmgr_register_bb_instrumentation_event(event_bb_analysis, NULL, NULL);
    dr_register_exit_event(event_exit);

    if (dr_is_notify_on()) {
        dr_fprintf(STDERR, "[+] Block coverage is running ...\n");
    }
}

// ------------------------------------------------------------------------------------------------
