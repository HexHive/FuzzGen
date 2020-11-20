# FuzzGen: Automatic Fuzzer Generation
### Kyriakos Ispoglou - ispo@google.com
___

```
      ___        ___           ___           ___           ___           ___           ___
     /\__\      /\  \         /\__\         /\__\         /\__\         /\__\         /\  \
    /:/ _/_     \:\  \       /::|  |       /::|  |       /:/ _/_       /:/ _/_        \:\  \
   /:/ /\__\     \:\  \     /:/:|  |      /:/:|  |      /:/ /\  \     /:/ /\__\        \:\  \
  /:/ /:/  / ___  \:\  \   /:/|:|  |__   /:/|:|  |__   /:/ /::\  \   /:/ /:/ _/_   _____\:\  \
 /:/_/:/  / /\  \  \:\__\ /:/ |:| /\__\ /:/ |:| /\__\ /:/__\/\:\__\ /:/_/:/ /\__\ /::::::::\__\
 \:\/:/  /  \:\  \ /:/  / \/__|:|/:/  / \/__|:|/:/  / \:\  \ /:/  / \:\/:/ /:/  / \:\~~\~~\/__/
  \::/__/    \:\  /:/  /      |:/:/  /      |:/:/  /   \:\  /:/  /   \::/_/:/  /   \:\  \
   \:\  \     \:\/:/  /       |::/  /       |::/  /     \:\/:/  /     \:\/:/  /     \:\  \
    \:\__\     \::/  /        |:/  /        |:/  /       \::/  /       \::/  /       \:\__\
     \/__/      \/__/         |/__/         |/__/         \/__/         \/__/         \/__/

                            FuzzGen - Automatic Fuzzer Generation
```
___


### Introduction

*FuzzGen*, is a tool for automatically synthesizing fuzzers for complex libraries in a given
environment. *FuzzGen* leverages a whole system analysis to infer the library’s interface and
synthesizes fuzzers specifically for that library. 

*FuzzGen* is fully automatic can be applied to a wide range of libraries. The, the generated fuzzers
leverage LibFuzzer to achieve better code coverage and expose bugs that reside deep in the library.


For more details please refer to our
[USENIX Security'20 paper](https://www.usenix.org/system/files/sec20fall_ispoglou_prepub.pdf).


### Build Instructions

To build *FuzzGen*, follow the classic `cmake - make` process:
```
# OPTIONAL: If you want to use a specific LLVM version
export LLVM_DIR=/path/to/llvm/build

cd $FUZZGEN_HOME_DIR
mkdir build
cd build
cmake ..
make -j$(nproc)
```

Note that we originally used LLVM 6 to compile the code, while it may work with other
versions of LLVM, some code changes will be necessary.

Also don't forget to adjust the following MACROs in `src/compose.h` according
to your needs:
```C++
#define ANDROID_TARGET_DEV  "aosp_walleye-userdebug"
#define ANDROID_FUZZ_DIR    "/tools/fuzzers/fuzzgen_files"
#define ANDROID_MAKE_JOBS   16
```

The preprocessor is a clang plugin, so building it requires more effort. First, copy the
[preprocessor](./src/preprocessor) directory under
`$LLVM_SRC/tools/clang/tools` and change the directory name to fuzzgen, add the following line in 
`$LLVM_SRC/tools/clang/tools/CMakeLists.txt`:
```
add_clang_subdirectory(fuzzgen)
```

Then, build the LLVM again. The preprocessor plugin will show up under
`$BUILD_LLVM_DIR/bin` directory.


### Running the PreProcessor

The first step to run *FuzzGen*, is to generate the metadata file. To do this,
run the preprocessor as follows:
```
    $BUILD_LLVM_DIR/bin/fuzzgen-preprocessor       \
        -outfile=$LIBNAME.meta                     \
        -library-root=/path/to/Android/home/       \ 
        $(find /path/to/all/library/source/files/) \
```

**WARNING:** In this approach we simply pass all source files in our plugin. However, it is possible
for clang to fail (even if running with `-fsyntax-only` option) to resolve MACROs and header file
names and therefore AST generation may be incomplete. That is, it is possible for some nodes in the
AST to be NULL, since clang cannot properly resolve them. This in turn, will result in incomplete
information in the metadata file, which is possible to cause *FuzzGen* to miss information during
fuzzer generation. To address this issue, you can use `compile_commands.json` file to get the exact
set of flags used to build the library, so clang will generate complete ASTs.


### Obtaining the LTO for the library

The second step is to obtain the *Link Time Optimization* (LTO) for the target library. That is, to
link all individual LLVM-IR files into a single one, so *FuzzGen* can analyze the whole library at
once.

To do that, add the following flags to the `Android.bp` to emit the LLVM IR:
```
    cflags: [
      "-save-temps",
      "-S -emit-llvm",
      "-m64"                // for 64 bit data layouts
    ],
```

This will produce multiple bitcode (`*.bc`) files under Android's root directory. To coalesce all
these bitcode file into a single one (LTO) use the `llvm-link` tool. This will result in a single
bitcode file, but it will not be in readable format. To get the human-readable disassembled LLVM-IR
(`*.ll`) use `llvm-dis`. Note that *FuzzGen* requires the `*.ll` file as input.


### Obtaining the IR for the whole Android source tree

As mentioned earlier, *FuzzGen* performs a whole system analysis. For the Android case, it requires
access to every source file in Android. To obtain all LLVM-IR files for the whole Android, first
build AOSP using `showcommands` to get the exact path to `clang/clang++` python executables. Then
do the following changes to the clang and clang++ files (at function `invoke_compiler()`):

*clang*:
```
6,7c6
< import subprocess
<
---
>
87,98d85
<
<     print 'ARGV0', self.argv0
<     print 'EXECARG', self.execargs
<
<     try:
<       subprocess.check_call(self.execargs + ["-save-temps", "-S", "-m64", "-emit-llvm"])
<     except subprocess.CalledProcessError:
<       print 'FAILURE BUT WHO CARES?'
<     except OSError:
<       print 'OS FAILURE BUT WHO CARES?'
<
```

*clang++*:
```
< import subprocess
<
< print uniform(1, 10)
89,100d85
<
<     print 'ARGV0++', self.argv0
<     print 'EXECARG++', self.execargs
<
<     try:
<       subprocess.check_call(self.execargs + ["-save-temps", "-S", "-m64", -emit-llvm"])
<     except subprocess.CalledProcessError:
<       print 'FAILURE BUT WHO CARES?'
<     except OSError:
<       print 'OS FAILURE BUT WHO CARES?'
<
<
```

Please note that we need to invoke `subprocess.check_call` which spawns a new process (i.e., actual
compiler) and waits till returns. When we dump the bitcode files, no executable is generated, so
after this step, we need to execute `os.execv(self.argv0, self.execargs)` **without** the extra
arguments as well.

**NOTE:** If you operate on 32-bits do not add the `-m64` option.


### Running FuzzGen

The best way to understand how to run *FuzzGen* is to go through its command line help:
```
OVERVIEW: FuzzGen - Automatic Fuzzer Generation

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


USAGE: fuzzgen [options] <library.ll>

OPTIONS:

Fuzzer Generation Options:

  -analysis                 - Type of analysis to be performed
    =dumb                   -   DEPRECATED. Dumb fuzzing of all arguments
    =basic                  -   DataFlow analysis for each argument (not recommended)
    =deep                   -   DataFlow analysis with deep inspection for each argument (Default)
  -arch                     - Processor architecture of the fuzzed device
    =x86                    -   32-bit processor
    =x64                    -   64-bit processor (Default)
  -consumer-dir=<dir>       - Root directory where the LLVM IR of all consumers reside
  -lib-name=<name>          - Library name
  -max-buflen=<size>        - Maximum buffer size
  -max-depth=<depth>        - Maximum recursion depth (for internal analysis)
  -meta=<library.meta>      - Library metadata file
  -min-buflen=<size>        - Minimum buffer size
  -no-coalesce              - Disable AADG coalescing
  -no-failure               - Do not apply failure heuristic
  -no-permute               - Disable function permutations on-the-fly
  -outdir=<directory>       - Directory name to place the generated fuzzers
  -seed=<uint>              - Use a specific random seeds, to de-randomize variable names (Debug only)
  -visualize                - Visualize the Abstract API Dependence Graph
  -yes                      - Set default answer to 'yes' every time FuzzzGen prompts permission to continue

Fuzzer Generation Options for Android:

  -aux-lib=<lib-path>       - Auxiliary library's LLVM IR (with LTO)
  -aux-path=<aux-path>      - Auxiliary library's path inside Android source tree
  -lib-root=<root-dir>      - Root directory of the library (or AOSP directory for Android)
  -no-progressive           - Disable progressive fuzzer generation
  -path=<dir>               - Library path inside AOSP
  -shared-libs=<shared-lib> - Library's static module name
  -static-libs=<static-lib> - Library's static module name

General Options:

  -mode                     - FuzzGen operation mode
    =android                -   Generate fuzzers for Android (Default)
    =debian                 -   Generate fuzzers for Debian
    =dump_functions         -   Dump all library functions and exit
    =dump_api               -   Dump library API and exit
  Verbosity level:
    -v0                     - Display minimum status information
    -v1                     - Display basic status information (Default)
    -v2                     - Display detailed status information (Recommended)
    -v3                     - Display all status information (Not recommended)

Generic Options:

  -help                     - Display available options (-help-hidden for more)
  -help-list                - Display list of available options (-help-list-hidden for more)
  -version                  - Display the version of this program

```


## Running Scripts

*FuzzGen* comes with a lot of useful scripts to assist data collection and visualization under
[aux/](./aux) directory. Feel free to experiment with them.

As an example, to aggregate line coverage reports and plot the plot code coverage use the
[plot_libfuzzer_coverage.py](./aux/plot_libfuzzer_coverage.py) script as follows:
```
aux/plot_libfuzzer_coverage.py     \
    --fuzzgen_dir $FUZZGEN_RESULTS \
    --ispo_dir $MANUAL_RESULTS     \
    --fuzzer_name $FUZZERNAME
```

___
