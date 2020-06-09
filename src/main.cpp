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
 * main.cpp
 *
 * This is the main FuzzGen file. 
 *
 */
// ------------------------------------------------------------------------------------------------
#include "common.h"                                 // local includes
#include "root.h"
#include "analyze.h"
#include "internal.h"
#include "external.h"
#include "compose.h"
#include "infer_api.h"
#include "options.h"

#include "llvm/Support/CommandLine.h"               // llvm includes

#include <typeinfo>                                 // c++ includes
#include <iostream>
#include <sstream>
#include <vector>
#include <map>
#include <set>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>


#define ABORT_MSG      "Aborting execution... x(\n"
#define FUNCTIONS_FILE "funcs.txt"
#define API_FILE       "api.txt"

/* write functions to a file (1 per line) */
#define DUMP_FUNCTIONS_TO_FILE(functions, filename)                     \
    ofstream ofs(filename);                                             \
    if (!ofs) {                                                         \
        fatal() << "Cannot create file '" << filename << "'.\n";        \
        remark(v0) << "Error Message: '" << strerror(errno) << "'.\n";  \
        return false;                                                   \
    }                                                                   \
                                                                        \
    /* write functions one by one */                                    \
    for (auto ii=functions.begin(); ii!=functions.end(); ++ii) {        \
        ofs << *ii << "\n";                                             \
    }                                                                   \
                                                                        \
    ofs.close();                                                        \
                                                                        \
    info(v0) << "Functions dumped at '" << filename << "'.\n"

/* create a new directory */
#define MK_DIR(dirname)                                                         \
 if (mkdir(dirname, 0755) == -1) {                                              \
        if (errno == EEXIST) {                                                  \
            remark(v0) << "Directory '" << dirname << "' already exists.\n";    \
        } else {                                                                \
            fatal() << "Cannot create fuzzer directory '" << dirname << "'.\n"; \
                                                                                \
            remark(v0) << "Error Message: '" << strerror(errno) << "'.\n"       \
                       << ABORT_MSG;                                            \
            return -1;                                                          \
        }                                                                       \
    }


using namespace llvm;
using namespace std;



// ------------------------------------------------------------------------------------------------
// Globals
//
int Info::verbosityLevel;                           // verbosity level for stdout
Context ctx;                                        // execution context



// ------------------------------------------------------------------------------------------------
// Load the metadata file into the appropriate data structs. Function assumes that the file
// strictly follows the right format.
//
bool loadMeta(string metafile) {

/* Sometimes preprocessor analysis fails due to compilation errors, because we process files
 * individually and not through the regular compilation process. Thus, a function's metadata
 * can be empty (a function without parameter names, signed/constant parameters). However, 
 * the same function appears multiple times in the metadata file (as include headers and
 * therefore function declarations exists in multiple source files). Instead of overwriting
 * the function's metadata with the latest entry, we keep only the one entry with the "most"
 * information (i.e., metadata).
 */
#define ADD_IF_GREATER(dict, key, val)      \
    if (dict.find(key) == dict.end() ||     \
        dict[key].size() < val.size()) {    \
            dict[key] = val;                \
    }

/* dump an aggregate set */
#define DUMP(aggregate, msg)                                                        \
    info(v3) << msg << "\n";                                                        \
                                                                                    \
    for (auto ii=aggregate.begin(); ii!=aggregate.end(); ++ii) {                    \
        string par("");                                                             \
                                                                                    \
        for (auto jj=ii->second.begin(); jj!=ii->second.end(); par+=*jj++ + ", ")   \
            { }                                                                     \
                                                                                    \
        if (par.size() > 2) {                                                       \
            par.pop_back();     /* drop the last comma (if exists) */               \
            par.pop_back();                                                         \
        }                                                                           \
                                                                                    \
        info(v3) << "  " << ii->first << " " << par << "\n";                        \
    }    


    /* available metadata labels */
    enum MetaLabel { FUNCTION=1, GLOBAL, PARAMS, ARRAYREF, INCLDEP, 
                     STRDECL, SIGNPARAM, CONSTPARAM };

    ifstream ifs(metafile);
    string   line;
    int      mode = -1;


    info(v0) << "Loading metadata file...\n";

    if (!ifs) {
        fatal() << "Cannot open metadata file. Abort.\n";
        return false;
    }


    /* process metadata line by line */
    while (getline(ifs, line)) {
        if (line.empty() || line[0] == '#') {       // skip empty lines and comments
            continue;
        }

        if (line == "@functionhdrs") {              // @header label found
            mode = FUNCTION;
            continue;
        } if (line == "@globalhdrs") {              // @global label found
            mode = GLOBAL;
            continue;
        }  else if (line == "@params") {            // @params label found
            mode = PARAMS;
            continue;
        } else if (line == "@arrayrefs") {          // @arrayref label found
            mode = ARRAYREF;
            continue;
        } else if (line == "@includedeps") {        // @includedeps label found
            mode = INCLDEP;
            continue;
        } else if (line == "@structdecls") {       // @structdecls label found
            mode = STRDECL;
            continue;
        } else if (line == "@signedparams") {       // @signedparams label found
            mode = SIGNPARAM;
            continue;
        } else if (line == "@constparams") {       // @signedparams label found
            mode = CONSTPARAM;
            continue;
        }


        /* process line in "function" mode */
        if (mode == FUNCTION) {
            istringstream iss(line);
            string fun, mod;

            iss >> fun >> mod;                      // ex: "printf bionic/libc/include/stdio.h"

            /* temporary fix: Drop modules in out/ directory */
            if (mod.compare(0, 4, "out/")) { 
                ctx.header[fun] = mod;
            }
        }

        /* process line in "global" mode */
        else if (mode == GLOBAL) {
            istringstream iss(line);
            string glo, mod, type;

            iss >> glo >> mod >> type;

            /* if global was a typedef, mark it (needed for the composer) */
            if (type == "typedef") ctx.tDef[glo] = true;

            ctx.global[glo] = mod;
        }

        /* process line in "parameters" mode */
        else if (mode == PARAMS) {
            istringstream iss(line);
            vector<string> param;
            string fun, par;

            iss >> fun;                             // ex: "somefunc arg1 arg4 arg5"
            while (iss >> par) param.push_back(par);

            ADD_IF_GREATER(ctx.paramNames, fun, param);
        }

        /* process line in "array reference" mode */
        else if (mode == ARRAYREF) {
            istringstream iss(line);
            set<string> param;
            string fun, par;

            iss >> fun;                             // ex: "somefunc arg1 arg4 arg5"
            while (iss >> par) param.insert(par);

            ADD_IF_GREATER(ctx.arrayRef, fun, param);
        }

        /* process line in "include dependencies" mode */
        else if (mode == INCLDEP) {
            istringstream iss(line);
            vector<string> deps;
            string mod, incl;

            iss >> mod;
            while (iss >> incl) deps.push_back(incl);

            ADD_IF_GREATER(ctx.inclDep, mod, deps);
        }

        /* process line in "struct declaration" mode */
        else if (mode == STRDECL) {
            istringstream iss(line);
            vector<string> fields;
            string strct, field;

            iss >> strct;
            while (iss >> field) fields.push_back(field);

            fields.push_back("__extrac_field__");
            ADD_IF_GREATER(ctx.strFields, strct, fields);
        }

        /* process line in "signed parameter" mode */
        else if (mode == SIGNPARAM) {
            istringstream iss(line);
            set<string>   param;
            string        fun, par;

            iss >> fun;                             // ex: "somefunc arg1 arg4 arg5"
            while (iss >> par) param.insert(par);

            ADD_IF_GREATER(ctx.signParam, fun, param);
        }

        /* process line in "const parameter" mode */
        else if (mode == CONSTPARAM) {
            istringstream iss(line);
            set<string>   param;
            string        fun, par;

            iss >> fun;                             // ex: "somefunc arg1 arg4 arg5"
            while (iss >> par) param.insert(par);

            ADD_IF_GREATER(ctx.constParam, fun, param);
        }
    }


    ifs.close();

    info(v0) << "Done.\n";


    /* print metadata to the user */
    info(v3) << "Dumping includes for each function...\n";

    for (auto ii=ctx.header.begin(); ii!=ctx.header.end(); ++ii)
        info(v3) << "  " << ii->first << "() defined in " << ii->second << "\n";


    info(v3) << "Dumping includes for each global symbol...\n";

    for (auto ii=ctx.global.begin(); ii!=ctx.global.end(); ++ii) {
        info(v3) << "  " << ii->first << " defined in " << ii->second
                 << (ctx.tDef.find(ii->first) == ctx.tDef.end() ? "" : " (T)") << "\n";
    }

    /* print other sets one by one */
    DUMP(ctx.inclDep,    "Dumping includes dependencies for each module...");
    DUMP(ctx.arrayRef,   "Dumping array references for each function...");
    DUMP(ctx.paramNames, "Dumping parameter names for each function...");
    DUMP(ctx.signParam,  "Dumping signed parameters for each function...");
    DUMP(ctx.constParam, "Dumping constant parameters for each function...");
    DUMP(ctx.strFields,  "Dumping struct fields for each module...");

    return true;

#undef DUMP
#undef ADD_IF_GREATER
}



// ------------------------------------------------------------------------------------------------
// Initialize the environment and launch fuzzgen components.
//
bool parseArguments(int argc, char **argv) {

/* display a message when an argument is missing*/
#define SHOW_MISSING(flag, msg)                                               \
    fatal() << msg << " is missing. Please specify '" << flag << "' flag.\n"; \
    missing = true


    // --------------------------------------------------------------------- //
    //                      * Initialize Environment *                       //
    // --------------------------------------------------------------------- //
    cl::HideUnrelatedOptions(RelatedOpts);
    cl::ParseCommandLineOptions(argc, argv, helpMessage);

    Info::verbosityLevel = argVerbosity;            // set verbosity level

    ctx.yes = argYesToAll;
  

    // --------------------------------------------------------------------- //
    //                   * Verify Command Line Arguments *                   //
    // --------------------------------------------------------------------- //
    bool missing = false;


    remark(v0) << "Please make sure that command line arguments are not malformed. "
               << "I'm too lazy for an extensive argument checking :\\\n";

    switch (argMode) {
        case dump_functions:
            /* no additional arguments are required */
            break;

        case dump_api:
            if (argMeta        == "") { SHOW_MISSING("-meta", "Metadata file"); }
            if (argConsumerDir == "") { SHOW_MISSING("-consumer-dir", "Consumer directory"); }
            if (argLibRoot     == "") { SHOW_MISSING("-lib-root", "Library Root directory"); }

            if (argLibPath == ".") {
                
                warning() << "Library path is not set. This is OK for Debian libraries, but "
                          << "for Android you must specify '-path' option\n";


                warning() << "UPDATE: without '-path' on Android libs FuzzGen may crash\n";

                if (!continueExecution("", &ctx)) {
                    return false;
                }
            }

            break;

        case android:            
            if (argStaticLibs == "" && argSharedLibs == "") {
                SHOW_MISSING("-static-libs", "Static library list");
                SHOW_MISSING("-shared-libs", "Shared library list");
                
                remark(v0) << "Set at least one of '-static-libs' or '-shared-libs'.\n";
            }

            if (argLibPath   == ".") { SHOW_MISSING("-path", "Library path in AOSP"); }
            if (argFuzzerDir == "")  { SHOW_MISSING("-outdir", "Fuzzer output directory"); }

            // do not break

        case debian:
            if (argMeta        == "") { SHOW_MISSING("-meta", "Metadata file"); }
            if (argConsumerDir == "") { SHOW_MISSING("-consumer-dir", "Consumer directory"); }
            if (argLibRoot     == "") { SHOW_MISSING("-lib-root", "Library Root directory"); }
            if (argLibName     == "") { SHOW_MISSING("-lib-name", "Library name"); }

            break;

        default:
            // invalid mode?
            break;
    }

    /* if at least 1 argument is missing, abort */
    if (missing) return false;


    // --------------------------------------------------------------------- //
    //                         * Adjust Arguments *                          //
    // --------------------------------------------------------------------- //
#define DROP_FIRST_SLASH(str) if (str[0]     == '/') str.erase(0,1)
#define DROP_LAST_SLASH(str)  if (str.back() == '/') str.pop_back()

    DROP_FIRST_SLASH(argLibPath);
    DROP_FIRST_SLASH(argAuxLibPath);

    DROP_LAST_SLASH(argConsumerDir);
    DROP_LAST_SLASH(argFuzzerDir);

#undef DROP_LAST_SLASH
#undef DROP_FIRST_SLASH


    // --------------------------------------------------------------------- //
    //                         * Initialize Context                          //
    // --------------------------------------------------------------------- //
    /* initialize execution context (shared across all modules) */
    ctx.progName   = argv[0];
    ctx.mode       = argMode;
    ctx.libRoot    = argLibRoot;
    ctx.libName    = argLibName;
    ctx.libPath    = argLibPath;
    ctx.staticLibs = argStaticLibs;
    ctx.sharedLibs = argSharedLibs;
    ctx.auxLibPath = argAuxLibPath;
    ctx.fuzzerDir  = argFuzzerDir;
    ctx.minbuflen  = argMinBufLen;
    ctx.maxbuflen  = argMaxBufLen;
    ctx.maxDepth   = argMaxRecursionDepth;
    ctx.visualize  = argVisualize;
    ctx.seed       = argSeed;    
    ctx.flags      = argAnalysis | // (argNoExternal    ? 0 : FLAG_EXTERNAL) |
                                   (argNoPermute     ? 0 : FLAG_PERMUTE)  |
                                   (argNoFailure     ? 0 : FLAG_FAILURE)  |
                                   (argNoCoalesce    ? 0 : FLAG_COALESCE) |
                                   (argArch64        ? FLAG_ARCH64 : 0)   |
                                   (argNoProgressive ? 0 : FLAG_PROGRESSIVE);

    /* all good :) */
    return true;

#undef SHOW_MISSING
}



// ------------------------------------------------------------------------------------------------
// Operation mode: dump_functions. Dump all functions from library.
//
bool dumpFunctions(string library) {
    AnalyzerNG  analyzer(&ctx);
    set<string> functions;                          // place all functions here


    info(v0) << "Dumping all functions from library ...\n";

    /* enumerate all functions from library */
    if (!analyzer.quickRun(library, new EnumFunctions(functions))) {
        fatal() << "Cannot run EnumFunctions module on library '" << argLibrary << "' file.\n";
        return false;                           // failure.
    }

    info(v1) << "Done. " << functions.size() << " functions found on library.\n";

    /* write all functions to a file */
    DUMP_FUNCTIONS_TO_FILE(functions, FUNCTIONS_FILE);

    remark(v0) << "To find all source files that use functions from this library, type "
               << "'grep --recursive --max-count=1 --file=" << FUNCTIONS_FILE << " $SRC_DIR'\n";

    return true;
}



// ------------------------------------------------------------------------------------------------
// Operation mode: dump_api. Infer library API and dump it to a file.
//
bool dumpAPI(string library, string libRoot, string libPath, string consumerDir) {
    /* load library's metadata */
    if (!loadMeta(argMeta)) {
        remark(v0) << "Metadata file is crucial for FuzzGen. Please make sure it's available.\n";
        return false;
    }


    InferAPI infer_api(library, libRoot, libPath, consumerDir, &ctx);

    info(v0) << "Inferring library API ...\n";

    if (!infer_api.inferAPI()) {
        fatal() << "Cannot infer library's API.\n";
        return false;
    }

    /* write functions to a file */
    DUMP_FUNCTIONS_TO_FILE(infer_api.getAPI(), API_FILE);

    return true;
}



// ------------------------------------------------------------------------------------------------
//  Entry point. Initialize the environment and launch fuzzgen components.
//
int main(int argc, char **argv) {
    vector<External *> external;
    set<string>        libAPI;                      // library's API
    set<string>        extAPI;                      // library's API used by external modules
    set<string>        extMods;                     // external modules

    vector<interwork::APICall*> intrlCalls;         // API call objects from internal analysis
    vector<ExternalObj *>       extObjs;            // API call objects from external analyses

    bool error = false;                             // no errors occurred


    // --------------------------------------------------------------------- //
    //                      * Initialize environment *                       //
    // --------------------------------------------------------------------- //
    if (!parseArguments(argc, argv)) {
        fatal() << "Please check again command line arguments.\n";
        return 0;
    }

    info(v0) << "Starting FuzzGen " << CURRENT_VERSION << " at " << now() << "\n";


    // --------------------------------------------------------------------- //
    //                * Operation Mode: Dump functions/api *                 //
    // --------------------------------------------------------------------- //
    if (argMode == dump_functions) {
        if (!dumpFunctions(argLibrary)) {    
            remark(v0) << ABORT_MSG;
            return -1;
        }

        return 0;

    } else if (argMode == dump_api) {        
        if (!dumpAPI(argLibrary, argLibRoot, argLibPath, argConsumerDir)) {
            remark(v0) << ABORT_MSG;
            return -1;
        }

        return 0;
    }


    // --------------------------------------------------------------------- //
    //                 * Operation Mode: Fuzzer Generation *                 //
    // --------------------------------------------------------------------- //  
    /* load library's metadata */
    if (!loadMeta(argMeta)) {
        remark(v0) << "Metadata file is crucial for FuzzGen. Please make sure it's available.\n";
        return -1;                                  // errors are fatal here
    }


    /* crate fuzzer directory (output) */
    MK_DIR(argFuzzerDir.c_str());

    /* create graphs directory */
    if (argVisualize) {
        MK_DIR(string(argFuzzerDir + "/graphs").c_str());
    }


    try {
        AnalyzerNG analyzer(&ctx);
        InferAPI   infer_api(argLibrary, argLibRoot, argLibPath, argConsumerDir, &ctx);
        

        // --------------------------------------------------------------------- //
        //                        * Infer Library's API *                        //
        // --------------------------------------------------------------------- //
        if (!infer_api.inferAPI()) {
            fatal() << "Cannot infer library's API.\n";

            remark(v0) << ABORT_MSG;
            return -1;
        }

        libAPI  = infer_api.getAPI();               // get API
        extAPI  = infer_api.getExtAPI();            // get "external" API
        extMods = infer_api.getExternalModules();   // get external modules


        // --------------------------------------------------------------------- //
        //                   * Infer Auxiliary Library's API *                   //
        // --------------------------------------------------------------------- //
        if (argMode == android && argAuxLibrary != "") {
            info(v1) << "Auxiliary library is used.\n";


            InferAPI infer_aux_api(argAuxLibrary, argLibRoot, argAuxLibPath, argConsumerDir, &ctx);

            if (!infer_aux_api.inferAPI()) {
                fatal() << "Cannot infer auxiliary library's API.\n";

                remark(v0) << ABORT_MSG;
                return -1;
            }


            /* merge APIs */
            set<string> auxlibAPI = infer_aux_api.getAPI(),
                        auxExtAPI = infer_aux_api.getExtAPI();
            

            info(v1) << "Merging APIs from original and auxiliary libraries...\n";

            for (auto ii=auxlibAPI.begin(); ii!=auxlibAPI.end(); ++ii) {
                libAPI.insert(*ii);
            }

            for (auto jj=auxExtAPI.begin(); jj!=auxExtAPI.end(); ++jj) {
                extAPI.insert(*jj);
            }
        }


        // DEPRECATED. I LEAVE IT HERE FOR REFERENCE
        //
        // // --------------------------------------------------------------------- //
        // //                         * Internal Analysis *                         //
        // // --------------------------------------------------------------------- //
        // if (argNoExternal) {                        // if no external modules are utilized
        //     /* run the internal module to prepare the interwork objects */
        //     if (!analyzer.quickRun(argLibrary, new Internal(&libAPI, &intrlCalls, &ctx))) {
        //         fatal() << "Cannot run Internal module on library file.\n";
        // 
        //         remark(v0) << ABORT_MSG;
        //         return -1;
        //     }
        // 
        //     Composer composer(argFuzzerDir, &ctx);            
        //     uint16_t currPool = composer.mkpool();  // create the first pool
        // 
        // 
        //     // if we have no external module, either put all functions to the same pool,
        //     // or put one function per pool, according to "-no-permute" argument"
        //     for (auto ii=intrlCalls.begin(); ii!=intrlCalls.end(); ++ii) {
        //         info(v2) << "Pushing function '" << (*ii)->name << "' into pool #" 
        //                  << currPool << "\n";
        // 
        //         /* if current pool has too many functions, split it */
        //         if (composer.size(currPool) >= MAX_FUNCS_PER_POOL) {
        //             warning() << "Pool #" << currPool << " has too many functions. Splitting...\n";
        // 
        //             currPool = composer.mkpool();
        //         }
        // 
        //         /* push function to the pool */
        //         if (!composer.push(currPool, *ii)) {
        //             fatal() << "Cannot push function to this pool.\n"
        //                     << "Cannot create function pools.\n";
        // 
        //             remark(v0) << ABORT_MSG;
        //             return -1;
        //         }
        // 
        //         if (!(ctx.flags & FLAG_PERMUTE)) {  // when permutations are disabled,
        //             currPool = composer.mkpool();   // each function goes to a different pool
        //         }
        //     }
        // 
        //     /* generate fuzzer */
        //     if (!composer.generate(FUZZER_SOURCE_EXTENSION, ctx.flags)) {
        //         fatal() << "Cannot generate fuzzer.\n";
        // 
        //         remark(v0) << ABORT_MSG;
        //         return -1;
        //     }
        // }


        // --------------------------------------------------------------------- //
        //                         * External Analysis *                         //
        // --------------------------------------------------------------------- //

        /* run internal module on all external functions to prepare the interwork objects */

        // NOTE: The only reason that we don't run internal module on libAPI, is for
        //       optimizations. If the library's API contains too many functions, but
        //       only a small portion of them is used by the external modules, then
        //       FuzzGen wastes cycles on analyzing a functions that will never be used.  
        //
        if (!analyzer.quickRun(argLibrary, new Internal(&extAPI, &intrlCalls, &ctx))) {
            fatal() << "Cannot run Internal module on library file.\n";

            remark(v0) << ABORT_MSG;
            return -1;
        }


        /* run internal analysis for the auxiliary library (if needed) */
        if (argMode == android && argAuxLibrary != "") {
            if (!analyzer.quickRun(argAuxLibrary, new Internal(&extAPI, &intrlCalls, &ctx))) {
                fatal() << "Cannot run Internal module on library file.\n";

                remark(v0) << ABORT_MSG;
                return -1;
            }
        }


        /* create the external analysis object */
        External *ext = new External(libAPI, intrlCalls, analyzer.modules, extObjs, &ctx);
        analyzer.addPass(ext);
        analyzer.addIR(argLibrary, MODULE_LIBRARY);

        /* push all external module to the analyzer */
        for (auto ii=extMods.begin(); ii!=extMods.end(); ++ii) {
            analyzer.addIR(*ii, MODULE_EXTERNAL);
        }

        /* collect all external (LLVM) modules */
        if (!analyzer.run()) {                
            fatal() << "Cannot run External modules + library file.\n";

            remark(v0) << ABORT_MSG;
            return -1;
        }

        /* base check. We may have dropped all external objects */
        if (extObjs.size() < 1) {
            fatal() << "No external objects created. Much sad :(\n";

            // remark(v0) << "If still want to generate a fuzzer, you can try again "
            //            << "with the '-no-external' option.\n"
            //            << ABORT_MSG;

            return -1;
        }

        vector<string> subdirs;                 // fuzzer subdirectories

        /* each external object is a separate fuzzer */
        for (auto ii=extObjs.begin(); ii!=extObjs.end(); ++ii) {
            string   currDir   = argFuzzerDir + "/" + (*ii)->name;
            Composer *composer = new Composer(currDir, &ctx);


            /* create fuzzer directory */
            MK_DIR(currDir.c_str());

            remark(v0) << "Synthesizing fuzzer from" << (*ii)->name << " ...\n";

            subdirs.push_back((*ii)->name);


            /* Generate pools (place "calls" into the appropriate pools.) */
            info(v1) << "Generating pools...\n";
       
            for (size_t i=0; i<(*ii)->calls.size(); ++i) {
                uint16_t currPool = composer->mkpool();


                for (auto jj=(*ii)->calls[i].begin(); jj!=(*ii)->calls[i].end(); ++jj) {
                    info(v2) << "Pushing function '" << (*jj)->name << "' into pool #" 
                             << currPool << "\n";

                    /* if current pool has too many functions, split it */
                    if (composer->size(currPool) >= MAX_FUNCS_PER_POOL) {
                        warning() << "Pool #" << currPool << " has too many functions. Splitting...\n";

                        currPool = composer->mkpool();
                    }

                    /* push function to the pool */
                    if (!composer->push(currPool, *jj)) {
                        fatal() << "Cannot push function to this pool.\n"
                                << "Cannot create function pools.\n";
                        
                        remark(v0) << ABORT_MSG;
                        return -1;
                    }

                    if (!(ctx.flags & FLAG_PERMUTE)) {  // when permutations are disabled,
                        currPool = composer->mkpool();   // each function goes to a different pool
                    }
                }
            }         

            info(v0) << "Done.\n";

            try {
                /* generate fuzzer */
                if (!composer->generate((*ii)->name, ctx.flags)) {
                    fatal() << "Cannot generate fuzzer.\n";

                    remark(v0) << ABORT_MSG;
                    return -1;
                }
            } catch(FuzzGenException &e) {
                fatal() << "An exception was thrown: " << e.what() << ".\n";

                remark(v0) << "Discarding current fuzzer '" << (*ii)->name << "'.\n";
                error = true;
            }

            delete composer;
        }            

        /* generate the global makefile */

        Composer::generateGlobalMakefile(argFuzzerDir, subdirs);

     } catch(FuzzGenException &e) {
        fatal() << "An exception was thrown: " << e.what() << ".\n";
        
        remark(v0) << ABORT_MSG;
        return -1;
    }


    /* There's no point releasing the external objects as we are already exiting the program */


    // --------------------------------------------------------------------- //
    //                        * Display statistics *                         //
    // --------------------------------------------------------------------- //
    info(v0) << "\n";
    info(v0) << "Printing various statistics:\n";
    info(v0) << "    Library Functions                      : " << ctx.stats.nFuncs   << "\n";
    info(v0) << "    API Functions                          : " << ctx.stats.nAPI     << "\n";
    info(v0) << "    API Functions used by external modules : " << ctx.stats.nAPIUsed << "\n";
    info(v0) << "    AADG information (before coalescing)   : " << ctx.stats.nAADG    << "\n";

    for (size_t i=0; i<ctx.stats.AADG.size(); ++i) {
        Context::AADGInfo &info = ctx.stats.AADG[i];

        info(v0) << "        #" << i+1 << ": " << info.nodes << " nodes, " 
                                << info.edges << " edges    \t(" << info.name << ")\n";
    }

    if (ctx.flags & FLAG_COALESCE) {
        info(v0) << "\n";
        info(v0) << "    AADG information (after coalescing)    : " << ctx.stats.nAADG_coal << "\n";

        for (size_t i=0; i<ctx.stats.AADG_coal.size(); ++i) {
            Context::AADGInfo &info = ctx.stats.AADG_coal[i];

            info(v0) << "        #" << i+1 << ": " << info.nodes << " nodes, " 
                                    << info.edges << " edges    \t(" << info.name << ")\n";
        }

    } else {
        info(v0) << "    AADG coalescing was disabled.\n";
    }

    info(v0)   << "\n";

    if (!error) remark(v0) << "FuzzGen finished successfully!\n";
    else        remark(v0) << "FuzzGen finished with errors. Much Sad :(\n";


    remark(v0) << "Have a nice day :)\n";

    return 0;
}

// ------------------------------------------------------------------------------------------------
