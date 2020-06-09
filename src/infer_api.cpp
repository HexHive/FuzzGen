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
 * select.cpp
 *
 * This module infers library's API by leveraging the external modules. The process of inferring
 * the API is the following: First we get all "valid" functions from library (check EnumFunctions
 * for definition of a valid function). Then we search in all LLVM IR modules in consumer directory
 * looking for modules that invoke any of these functions. For each of these modules, we extract 
 * all #include files contained in the source file that created this module (as the IR does not
 * contain any information about #includes). Finally we look at the metadata and we extract all
 * functions that are declared in each of these include headers. This will be our API.
 *
 */
// ------------------------------------------------------------------------------------------------
#include "infer_api.h"
#include "root.h"
#include "analyze.h"
#include "blacklist.h"

#include <sstream>
#include <fstream>
#include <cstdlib>
#include <stack>
#include <cstring>
#include <unistd.h>
#include <dirent.h>                             // *nix includes
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>


using namespace std;

// ------------------------------------------------------------------------------------------------

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * *                                                                                           * *
 * *                                   ENUM FUNCTIONS CLASS                                    * *
 * *                                                                                           * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// ------------------------------------------------------------------------------------------------
// Globals
//
char EnumFunctions::ID = 0;



// ------------------------------------------------------------------------------------------------
// Constructor. Initialize class members.
//
EnumFunctions::EnumFunctions(set<string> &funcs) : ModulePass(ID), funcs(funcs) {
    info(v2) << "EnumFunctions module started.\n";
}



// ------------------------------------------------------------------------------------------------
// Overload this function to specify the required analyses.
//
void EnumFunctions::getAnalysisUsage(AnalysisUsage &au) const {
    au.setPreservesAll();
}


// ------------------------------------------------------------------------------------------------
// Module pass. Search for all valid functions in the module. Filter out functions that blacklisted,
// do not have a body or do no have an external linkage (i.e., they are not externally visible). 
//
bool EnumFunctions::runOnModule(Module &M) {

    /* iterate over each function */
    for (Module::const_iterator ii=M.begin(); ii!=M.end(); ++ii) {

        /* make sure that is not blacklisted */
        if (!Root::inBlacklist(ii->getName())) {

            /* make sure that it has a function body */
            if (!ii->isDeclaration()) {

                /* make sure that is externally visible */
                if (ii->getLinkage() == GlobalValue::LinkageTypes::ExternalLinkage) {                

                    /* all checks have passed. Add function to the set */
                    funcs.insert(string(ii->getName()));
 
                    info(v3) << "Library function '"  << ii->getName() << "' found.\n";
                }
            }
        }
    }

    /* we didn't modify the module, so return false */
    return false;
}



// ------------------------------------------------------------------------------------------------

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * *                                                                                           * *
 * *                                    EXTRACT PATH CLASS                                     * *
 * *                                                                                           * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// ------------------------------------------------------------------------------------------------
// Globals
//
char ExtractPath::ID = 0;



// ------------------------------------------------------------------------------------------------
// Constructor. Initialize class members.
//
ExtractPath::ExtractPath(string &path) : ModulePass(ID), path(path) {
    info(v2) << "ExtractPath module started.\n";
}



// ------------------------------------------------------------------------------------------------
// Overload this function to specify the required analyses.
//
void ExtractPath::getAnalysisUsage(AnalysisUsage &au) const {
    au.setPreservesAll();
}



// ------------------------------------------------------------------------------------------------
// Module pass. Simply grab source filename.
//
bool ExtractPath::runOnModule(Module &M) {
    path = string(M.getSourceFileName());           // copy string as it's a reference.

    /* we didn't modify the module, so return false */
    return false;
}



// ------------------------------------------------------------------------------------------------

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * *                                                                                           * *
 * *                                      INFER API CLASS                                      * *
 * *                                                                                           * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// ------------------------------------------------------------------------------------------------
// Constructor. Simply initialize class members.
//
InferAPI::InferAPI(string libMod, string libRoot, string libPath, string consumerDir, Context *ctx)
        : ctx(ctx), libMod(libMod), libRoot(libRoot), libPath(libPath), consumerDir(consumerDir) {

    info(v0) << "InferAPI module started.\n";    
}



// ------------------------------------------------------------------------------------------------
// This is a wrapper of the internal search.
//
bool InferAPI::searchModules() {
    modules.clear();

    return searchModules(consumerDir);
}



// ------------------------------------------------------------------------------------------------
// Filter an API function.
//
bool InferAPI::filter(string name) {
    
    /* function names that contain "bad" names can't be part of API */
    for (auto ii=blacklist.begin(); ii!=blacklist.end(); ++ii) {
        if (name.find(*ii) != string::npos) {
            return false;                           // function can't pass the filter
        }
    }

    return true;                                    // filter ok
}



// ------------------------------------------------------------------------------------------------
// Search (recursively) the whole root directory looking for modules that use library functions.
// The searching has to be fast due to the large number of candidate modules. Therefore, parsing
// and analyzing each file will have a huge impact in performance.
//
// A quick n' dirty way to deal with that is to "grep" the files looking for names of the root
// functions. Although it's possible to have false positives, it's impossible to miss any
// modules (unless code is obfuscated :P). Such modules will be discarded later on.
//
// OPT: Use multi-threading to boost performance.
//
// NOTE: This is a unix-specific implementation.
//
bool InferAPI::searchModules(string currDir) {
    DIR           *dir;
    struct dirent *dent;
    struct stat    st;
    string         path;


    info(v3) << "Visiting: " << currDir << "\n";

    /* open current directory */
    if ((dir = opendir(currDir.c_str())) == NULL) {
        fatal() << "Cannot open current directory '" << currDir << "'. Abort\n";

        remark(v0) << "Error Message: '" << strerror(errno) << "'.\n";
        return false;
    }


    /* for each file in that directory */
    while ((dent = readdir(dir)) != NULL) {
        path = currDir + "/" + dent->d_name;        // build full path

        if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, "..")) {
            continue;                               // skip these guys
        }

        if (stat(path.c_str(), &st) == 0) {
            if (st.st_mode & S_IFDIR) {
                /* recursively search in sub-directories */
                searchModules(path);                // ignore return value
            }

            else if (st.st_mode & S_IFREG) {
                string ext = path.substr(path.find_last_of(".") + 1),
                       line;


                /* skip non IR files */
                if (ext != "ll") continue;

                ifstream ifs(path);                 // open IR file

                if (!ifs) {
                    fatal() << "Cannot open '" << path << "'. Abort.\n";

                    remark(v0) << "Error Message: '" << strerror(errno) << "'.\n";
                    return false;                    // failure
                }


                /* process IR file line by line */
                while (getline(ifs, line)) {
                    if (line.empty()) continue;     // skip empty lines

                    /* check if each root function is included in this line */
                    for (auto ii=functions.begin(); ii!=functions.end(); ++ii) {

                        if (line.find("@" + *ii) != string::npos) {

                            if (extAPIset.find(*ii) == extAPIset.end()) {
                                /* ok, function found (print only once) */
                                info(v1) << "Module '" << path << "' invokes '" << *ii << "'!\n";
                            }

                            /* remember this module */
                            modules.insert(path);


                            if (!filter(*ii)) {
                                info(v1) << "    External API function is discarded by filter.\n";
                            } else {
                                extAPIset.insert(*ii);  // external API function found
                                APIset.insert(*ii);     // add it to the API set as well                                
                            }
                        }
                    }
                }

                ifs.close();
            }

            else {
                /* file is of unknown type */
                fatal() << "File '" << path << "' is of unknown type.\n";
            }

        } else {
            fatal() << "stat() error. Much sad. Skipping current file\n";

            remark(v0) << "Error Message: '" << strerror(errno) << "'.\n";
        }
    }

    closedir(dir);

    return true;                                    // success!
}



// ------------------------------------------------------------------------------------------------
// Find the full path for an included header. Some header files may include other header files,
// which may not be on the same path (e.g., if "foo.h" contains the line #include "bar.h", it
// doesn't means that foo.h and bar.h are under the same directory). This is because makefiles may
// add multiple subdirectories under the same $INCLUDE_DIRS path. Thus we have to search in all
// subdirectories till we find the desired file. (In case that we have >1 files with the same name
// we will have issues, but this is extremely rare to happen).
//
//
// NOTE: This is a unix-specific implementation as well.
//
string InferAPI::findHeaderPath(string header) {
    DIR           *dir; 
    struct dirent *dent;
    struct stat    st;
    string         path;
    stack<string>  S;

    
    info(v2) << "Searching for full path of '" << header << "' \n";

    S.push(libPath);                                // root directory

    while (!S.empty()) {
        string curr = S.top(),
               full = libRoot + "/" + curr;


        S.pop();

        /* open current directory */
        if ((dir = opendir(full.c_str())) == NULL) {
            fatal() << "Cannot open current directory '" << full << "'. Abort\n";

            remark(v0) << "Error Message: '" << strerror(errno) << "'.\n";
            return "";                              // failure
        }


        /* for each file in that directory */
        while ((dent = readdir(dir)) != NULL) {
            string file = full + "/" + dent->d_name;

            if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, "..")) {
                continue;                               // skip these guys
            }

            if (stat(file.c_str(), &st) == 0) {
                if (st.st_mode & S_IFDIR) {
                    /* add sub-directory to the stack */
                    S.push(curr + "/" + dent->d_name);

                } else if (st.st_mode & S_IFREG) {

                    // if (!strcmp(dent->d_name, header.c_str())) {
                    // TODO: this is a quick path. Change it.
                    if (header == "string.h") continue;
                    if (isSuffix(header, file)) {
                        /* include found. Return full path */
                        info(v2) << "Full path of '" << header << "' is '"
                                 << curr + "/" + dent->d_name << "'. \n";


                        return curr + "/" + dent->d_name;
                    }
                }
            } else {
                fatal() << "stat() error. Much sad. Skipping current file\n";

                remark(v0) << "Error Message: '" << strerror(errno) << "'.\n";
            }
        }

        closedir(dir);                              // close directory

    }


    info(v2) << "Cannot find full path of '" << header << "' \n"; 
 
    return "";                                    // failure
}



// ------------------------------------------------------------------------------------------------
// Extract all #include headers from a source file.
//
// NOTE: This is a unix-specific implementation as well.
//
// TODO: What's our for unbounded recursions. It can occur with malformed header files.
//
bool InferAPI::extractHeaders(string sourcePath, set<string> &includes) {
    string   fullSourcePath = libRoot + "/" + sourcePath;
    string   line;
    ifstream ifs(fullSourcePath);                   // open source file


    includes.clear();                               // clear any leftovers

    if (!ifs) {
        fatal() << "Cannot open '" << fullSourcePath << "'. Abort.\n";

        remark(v0) << "Error Message: '" << strerror(errno) << "'.\n";
        return false;                               // failure.
    }


    /* process source file line by line */
    while (getline(ifs, line)) {
        if (line.empty()) continue;                 // skip empty lines

        /* found an #include directive? */
        if (line.find("#include") != string::npos) {
            // OPT: This approach is naive but it works fine. Use regular expressions instead.

            size_t st = line.find("\""),            // get index of the 1st quote
                   en = line.find("\"", st+1);      // get index of the 2nd quote

            if (st == string::npos || en == string::npos) {

                // #include is angled <>. Ignore it.
                // UPDATE: libvorbis has anlged includes: "#include <vorbis/codec.h>" 
                st = line.find("<");                // give it a 2nd chance
                en = line.find(">", st+1);

                if (st == string::npos || en == string::npos) {
                    continue;
                }
            }


            string header  = line.substr(st+1, en-st-1),
                   hdrPath = findHeaderPath(header);                   
            set<string> nestedIncl;


            /* include found. Extract file. */
            info(v1) << "    Include header '" << header << "' found.\n";

            /* discard includes from test directories */
            if (hdrPath.find("tests") != string::npos) {
                info(v1) << "       Discarding header is it's under test directory.\n";

                continue;
            }

            /* discard includes that you can't retrieve their paths */
            if (hdrPath == "") {
                info(v1) << "       Discarding header is it cannot retrieve its path.\n";
                continue;
            }

            /* discard blacklisted headers (TODO: Code a better blacklist) */
            if (header == "arm/fixed_arm64.h" ||
                header == "arm/fixed_armv4.h" ||
                header == "arm/fixed_armv5e.h" ||
                header == "x86/x86cpu.h" ||
                header == "arm/armcpu.h" ||
                header == "mips/fixed_generic_mipsr1.h" ||
                header == "fixed_c5x.h" ||
                header == "fixed_debug.h"||
                header == "fixed_generic.h" ||
                header == "arm/fft_arm.h" ||
                header == "arm/mdct_arm.h" ||
                header == "kiss_fft.h"
            ) {
                info(v1) << "       Discarding header, as it's blacklisted.\n";

                continue;
            }

            includes.insert(header);                // include in the list

            /* recursively extract the includes of the includes (assume no infinity loops) */ 
            extractHeaders(hdrPath, nestedIncl);

            /* "merge" the 2 sets */
            for (auto ii=nestedIncl.begin(); ii!=nestedIncl.end(); ++ii) {
                includes.insert(*ii); 
            }
        }
    }
  

    ifs.close();

    return true;
}



// ------------------------------------------------------------------------------------------------
// This is the actual function that infers the API.
//
bool InferAPI::inferAPI() {
    AnalyzerNG *analyzer = new AnalyzerNG(ctx);     // create an analyzer instance


    info(v1) << "Enumerating all functions from library ...\n";

    /* first enumerate all functions from library */
    if (!analyzer->quickRun(libMod, new EnumFunctions(functions))) {
        fatal() << "Cannot run EnumFunctions module on library '" << libMod << "' file.\n";
        return false;                               // failure.
    }

    info(v1) << "Done. " << functions.size() << " functions found on library.\n";

    ctx->stats.nFuncs = functions.size();



    /* then find all modules that use functions from this library */
    info(v1) << "Searching for consumers that utilize library functions ...\n";

    searchModules();
    
    info(v1) << "Done. " << modules.size() << " consumers found.\n";


    /*
     * Extract all includes from each module's source file. 
     * The API will be all declared functions (as defined in metadata) from all includes.
     * 
     * TODO: We can also analyze the source files for each include and look for function
     *       declarations in the "includes of the includes" and so on. So far without the
     *       recursion, API set is exact, so we don't implement the recursive version.
     */
    info(v1) << "Infering the actual API functions ...\n";

    for (auto ii=modules.begin(); ii!=modules.end(); ++ii) {
        string      modPath = "";                   // store module source path here
        set<string> includes;                       // store inculde headers for each file


        info(v1) << "Parsing module '" << *ii << "' ...\n";

        /* get the source file that corresponds to this module */
        if (!analyzer->quickRun(*ii, new ExtractPath(modPath))) {
            fatal() << "Cannot run EnumFunctions module on library '" << *ii << "' file.\n";
            return false;                           // failure
        }

        info(v2) << "Module '" << *ii << "' originated from '" << modPath << "'.\n";

        /* if module is "LTO-ed" (i.e., came from multiple sources), skip it */
        if (modPath == "llvm-link") {
            continue;
        }


        /* extract all include directives from the source file */
        if (!extractHeaders(modPath, includes)) {
            fatal() << "Cannot extract #include headers from '" << modPath << "'.\n";
            return false;                           // failure   
        }


        /* look in metadata file for all functions declared in this include */
        for (auto jj=includes.begin(); jj!=includes.end(); ++jj) {

            /* do a reverse lookup in the 'header' map */
            for (auto kk=ctx->header.begin(); kk!=ctx->header.end(); ++kk) {

                /* we don't need perfect match as kk->second is a full path */
                if (kk->second.find(*jj) != string::npos) {
                    
                    /* include found. Get it's function */
                    info(v1) << "API function '" << kk->first  << "' found!\n";
                    
                    if (filter(kk->first)) {                        
                        APIset.insert(kk->first);
                    } else {
                        info(v1) << "    Function is discarded by filter.\n";
                    }
                }
            }
        }    
    }
  
    info(v1) << "Done. " << APIset.size() << " API functions found but " 
             << extAPIset.size() << " functions are used by the external modules.\n";
    
    ctx->stats.nAPI     = APIset.size();
    ctx->stats.nAPIUsed = extAPIset.size();


    for (auto ii=extAPIset.begin(); ii!=extAPIset.end(); ++ii) {
        remark(v2) << "API function " << *ii << " is used by the external modules.\n";
    }


    delete analyzer;                                // free analyzer

    return true;                                    // success!
}



// ------------------------------------------------------------------------------------------------
// Return the inferred API set.
//
set<string> &InferAPI::getAPI() {
    return APIset;
}



// ------------------------------------------------------------------------------------------------
// Return the set of API calls that are used in the external modules.
//
set<string> &InferAPI::getExtAPI() {
    return extAPIset;
}



// ------------------------------------------------------------------------------------------------
// Return all external modules that use our library.
//
set<string> &InferAPI::getExternalModules() {
    return modules;
}

// ------------------------------------------------------------------------------------------------
