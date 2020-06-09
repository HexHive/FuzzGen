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
 * options.h
 *
 * Declarations for the command line options.
 */
// ------------------------------------------------------------------------------------------------
#ifndef LIBRARY_OPTIONS_H
#define LIBRARY_OPTIONS_H



// ------------------------------------------------------------------------------------------------
// Category to place all arguments.
//
cl::OptionCategory FuzzGenOpts_General("General Options");
cl::OptionCategory FuzzGenOpts_FuzzGen("Fuzzer Generation Options");
cl::OptionCategory FuzzGenOpts_Android("Fuzzer Generation Options for Android");
cl::OptionCategory FuzzGenOpts_Debian ("Fuzzer Generation Options for Debian");

// place all related options into an array
cl::OptionCategory *OptArray[5] = {
    &FuzzGenOpts_General, &FuzzGenOpts_FuzzGen, &FuzzGenOpts_Android, &FuzzGenOpts_Debian, nullptr
};

ArrayRef<cl::OptionCategory *> RelatedOpts(&OptArray[0], &OptArray[4]);

// help message to display
const string helpMessage = R"(FuzzGen - Automatic Fuzzer Generation

FuzzGen supports 4 modes of operation. You can choose mode with the '-mode' option.


A) Dump Functions (-mode=dump_functions):

   In this mode, FuzzGen dumps all functions declared in the library to a file and exits.
   Example:

        ./fuzzgen -mode=dump_functions <library.ll>


B) Dump API (-mode=dump_api):

   In this mode, FuzzGen, dumps inferred API from the library to a file and exits.
   To do this it requires: i) the consumer directory, ii) the metadata file, iii) the 
   library's root directory and -for Android libs only- iv) the library path inside AOSP.
   Example:

        ./fuzzgen -mode=dump_api -consumer-dir=libopus/consumers -meta=libopus.meta \
                  -lib-root=consumers/AOSP -path=external/libopus libopus/libopus_lto64.ll


C) Generate Fuzzers for Android (-mode=android):

    In this mode, FuzzGen synthesizes fuzzers for Android libraries.
    Example:
    
        ./fuzzgen -mode=android -analysis=deep -arch=x64 -no-progressive -lib-name=libhevc \
                  -meta=libhevc.meta -consumer-dir=libhevc/ext -lib-root=consumers/AOSP \
                  -path=/external/libhevc -outdir=fuzzers/libhevc -static-libs='libhevcdec' \
                  libhevc/libhevc_lto64.ll


D) Generage Fuzzers for Debian (-mode=debian):
    #TODO

)";



// ------------------------------------------------------------------------------------------------

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * *                                                                                           * *
 * *                              GENERAL COMMAND LINE ARGUMENTS                               * *
 * *                                                                                           * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// ------------------------------------------------------------------------------------------------
// The LLMV IR of the target library (must be obtained with LTO).
//
cl::opt<string> argLibrary(
    cl::Positional,
    cl::desc("<library.ll>"),
    cl::Required
);

// ------------------------------------------------------------------------------------------------
// FuzzGen operation mode.
//
cl::opt<OperationMode> argMode(
    "mode",
    cl::desc("FuzzGen operation mode"),
    cl::values(        
        clEnumVal(android,         "Generate fuzzers for Android (Default)"),
        clEnumVal(debian,          "Generate fuzzers for Debian"),
        clEnumVal(dump_functions,  "Dump all library functions and exit"),
        clEnumVal(dump_api,        "Dump library API and exit")
    ),
    cl::init(android),
    cl::cat(FuzzGenOpts_General)
);

// ------------------------------------------------------------------------------------------------
// Verbosity level (4 levels are enough).
//
cl::opt<Verbosity> argVerbosity(
    cl::values(
        clEnumVal(v0, "Display minimum status information"),
        clEnumVal(v1, "Display basic status information (Default)"),
        clEnumVal(v2, "Display detailed status information (Recommended)"),
        clEnumVal(v3, "Display all status information (Not recommended)")
    ),
    cl::desc("Verbosity level:"),
    cl::init(Verbosity::v1),
    cl::cat(FuzzGenOpts_General)
);



// ------------------------------------------------------------------------------------------------

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * *                                                                                           * *
 * *                         FUZZER GENERATION COMMAND LINE ARGUMENTS                          * *
 * *                                                                                           * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// ------------------------------------------------------------------------------------------------
// The target library's name.
//
cl::opt<string> argLibName(
    "lib-name",
    cl::desc("Library name"),
    cl::value_desc("name"),
    cl::cat(FuzzGenOpts_FuzzGen)
);

// ------------------------------------------------------------------------------------------------
// Type of analysis.
//
cl::opt<AnalysisType> argAnalysis(
    "analysis",
    cl::desc("Type of analysis to be performed"),
    cl::values(
        clEnumVal(dumb,  "DEPRECATED. Dumb fuzzing of all arguments"),
        clEnumVal(basic, "DataFlow analysis for each argument (not recommended)"),
        clEnumVal(deep,  "DataFlow analysis with deep inspection for each argument (Default)")
    ),
    cl::init(deep),    
    cl::cat(FuzzGenOpts_FuzzGen)
);

// ------------------------------------------------------------------------------------------------
// Verbosity level (4 levels are enough).
//
/*cl::opt<Verbosity> argFailureMode(
    cl::values(
        clEnumVal(v0, "Upon failure leave it to the user"),
        clEnumVal(v1, "Discard functions and all dependencies")
    ),
    cl::desc("Failure Handling"),
    cl::init(Verbosity::v1),
    cl::cat(FuzzGenOpts_General)
);*/

// ------------------------------------------------------------------------------------------------
// Architecture to follow (x86/x64).
//
cl::opt<ProcessorArch> argArch64(
    "arch",
    cl::values(
        clEnumVal(x86, "32-bit processor"),
        clEnumVal(x64, "64-bit processor (Default)")
    ),
    cl::desc("Processor architecture of the fuzzed device"),
    cl::init(x64),
    cl::cat(FuzzGenOpts_FuzzGen)
);

// ------------------------------------------------------------------------------------------------
// Root directory that contains with all external modules.
//
cl::opt<string> argConsumerDir(
    "consumer-dir",
    cl::desc("Root directory where the LLVM IR of all consumers reside"),
    cl::value_desc("dir"),
    cl::cat(FuzzGenOpts_FuzzGen)
);

// ------------------------------------------------------------------------------------------------
// Metadata file name.
//
cl::opt<string> argMeta(
    "meta",
    cl::desc("Library metadata file"),
    cl::value_desc("library.meta"),
    cl::cat(FuzzGenOpts_FuzzGen)
);

// ------------------------------------------------------------------------------------------------
// Output directory to place all generated fuzzers.
//
cl::opt<string> argFuzzerDir(
    "outdir",
    cl::desc("Directory name to place the generated fuzzers"),
    cl::value_desc("directory"),
    cl::cat(FuzzGenOpts_FuzzGen)
);

// ------------------------------------------------------------------------------------------------
// Root directory of AOSP.
//
cl::opt<string> argLibRoot(
    "lib-root",
    cl::desc("Root directory of the library (or AOSP directory for Android)"),
    cl::value_desc("root-dir"),
    cl::cat(FuzzGenOpts_Android)
);

// // ---------------------------------------------------------------------------------------------
// // Flag to disable analysis of external modules.
// //
// cl::opt<bool> argNoExternal(
//     "no-external",
//     cl::desc("Do not analyze external modules"),
//     cl::init(false),
//     cl::cat(FuzzGenOpts)
// );

// ------------------------------------------------------------------------------------------------
// Flag to disable on-the-fly function permutations (i.e., disable pools).
//
cl::opt<bool> argNoPermute(
    "no-permute",
    cl::desc("Disable function permutations on-the-fly"),
    cl::init(false),
    cl::cat(FuzzGenOpts_FuzzGen)
);

// ------------------------------------------------------------------------------------------------
// Flag to disable failure heuristic.
//
cl::opt<bool> argNoFailure(
    "no-failure",
    cl::desc("Do not apply failure heuristic"),
    cl::init(false),
    cl::cat(FuzzGenOpts_FuzzGen)
);

// ------------------------------------------------------------------------------------------------
// Flag to disable AADG coalescing.
//
cl::opt<bool> argNoCoalesce(
    "no-coalesce",
    cl::desc("Disable AADG coalescing"),
    cl::init(false),
    cl::cat(FuzzGenOpts_FuzzGen)
);

// ------------------------------------------------------------------------------------------------
// Flag to visualize all AADGs.
//
cl::opt<bool> argVisualize(
    "visualize",
    cl::desc("Visualize the Abstract API Dependence Graph"),
    cl::init(false),
    cl::cat(FuzzGenOpts_FuzzGen)
);

// ------------------------------------------------------------------------------------------------
// Minimum buffer length.
//
cl::opt<unsigned> argMinBufLen(
    "min-buflen",
    cl::desc("Minimum buffer size"),
    cl::value_desc("size"),
    cl::init(DEFAULT_MIN_BUFLEN),
    cl::cat(FuzzGenOpts_FuzzGen)
);

// ------------------------------------------------------------------------------------------------
// Maximum buffer length.
//
cl::opt<unsigned> argMaxBufLen(
    "max-buflen",
    cl::desc("Maximum buffer size"),
    cl::value_desc("size"),
    cl::init(DEFAULT_MAX_BUFLEN),
    cl::cat(FuzzGenOpts_FuzzGen)
);

// ------------------------------------------------------------------------------------------------
// Maximum recursion depth on internal analysis (i.e., "magic" module).
//
cl::opt<unsigned> argMaxRecursionDepth(
    "max-depth",
    cl::desc("Maximum recursion depth (for internal analysis)"),
    cl::value_desc("depth"),
    cl::init(DEFAULT_MAX_DEPTH),
    cl::cat(FuzzGenOpts_FuzzGen)
);

// ------------------------------------------------------------------------------------------------
// Use a predefined seed to have all variables the same names across executions.
//
cl::opt<unsigned> argSeed(
    "seed",
    cl::desc("Use a specific random seeds, to de-randomize variable names (Debug only)"),
    cl::init(0),
    cl::cat(FuzzGenOpts_FuzzGen)
);

// ------------------------------------------------------------------------------------------------
// Set default answer to "yes", every time that FuzzGen prompts a "Continue? [y/n] " message.
//
cl::opt<bool> argYesToAll(
    "yes",
    cl::desc("Set default answer to 'yes' every time FuzzzGen prompts permission to continue"),
    cl::init(false),
    cl::cat(FuzzGenOpts_FuzzGen)
);



// ------------------------------------------------------------------------------------------------

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * *                                                                                           * *
 * *                              ANDROID COMMAND LINE ARGUMENTS                               * *
 * *                                                                                           * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// ------------------------------------------------------------------------------------------------
// Library's path inside AOSP.
//
cl::opt<string> argLibPath(
    "path",
    cl::desc("Library path inside AOSP"),
    cl::value_desc("dir"),
    cl::init("."),                                  // for Debian this is current directory    
    cl::cat(FuzzGenOpts_Android)
);


// ------------------------------------------------------------------------------------------------
// Static libraries to include in the Android.mk.
//
cl::opt<string> argStaticLibs(
    "static-libs",
    cl::desc("Library's static module name"),
    cl::value_desc("static-lib"),
    cl::cat(FuzzGenOpts_Android)
);

// ------------------------------------------------------------------------------------------------
// Shared libraries to include in the Android.mk.
//
cl::opt<string> argSharedLibs(
    "shared-libs",
    cl::desc("Library's static module name"),
    cl::value_desc("shared-lib"),
    cl::cat(FuzzGenOpts_Android)
);

// ------------------------------------------------------------------------------------------------
// Flag to disable progressive fuzzer generation.
//
cl::opt<bool> argNoProgressive(
    "no-progressive",
    cl::desc("Disable progressive fuzzer generation"),
    cl::init(false),
    cl::cat(FuzzGenOpts_Android)
);

// ------------------------------------------------------------------------------------------------
// The LLMV IR of the auxiliary library (must be obtained with LTO).
//
cl::opt<string> argAuxLibrary(
    "aux-lib",
    cl::desc("Auxiliary library's LLVM IR (with LTO)"),
    cl::value_desc("lib-path"),
    cl::init(""),    
    cl::cat(FuzzGenOpts_Android)
);

// ------------------------------------------------------------------------------------------------
// Auxiliary library's path inside AOSP (optional).
//
cl::opt<string> argAuxLibPath(
    "aux-path",
    cl::desc("Auxiliary library's path inside Android source tree"),
    cl::value_desc("aux-path"),
    cl::cat(FuzzGenOpts_Android)
);



// ------------------------------------------------------------------------------------------------

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * *                                                                                           * *
 * *                               DEBIAN COMMAND LINE ARGUMENTS                               * *
 * *                                                                                           * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


// ------------------------------------------------------------------------------------------------
#endif
