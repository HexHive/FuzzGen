#!/bin/bash
# -------------------------------------------------------------------------------------------------
#
# Copyright (C) 2018 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
#      ___        ___           ___           ___           ___           ___           ___
#     /\__\      /\  \         /\__\         /\__\         /\__\         /\__\         /\  \
#    /:/ _/_     \:\  \       /::|  |       /::|  |       /:/ _/_       /:/ _/_        \:\  \
#   /:/ /\__\     \:\  \     /:/:|  |      /:/:|  |      /:/ /\  \     /:/ /\__\        \:\  \
#  /:/ /:/  / ___  \:\  \   /:/|:|  |__   /:/|:|  |__   /:/ /::\  \   /:/ /:/ _/_   _____\:\  \
# /:/_/:/  / /\  \  \:\__\ /:/ |:| /\__\ /:/ |:| /\__\ /:/__\/\:\__\ /:/_/:/ /\__\ /::::::::\__\
# \:\/:/  /  \:\  \ /:/  / \/__|:|/:/  / \/__|:|/:/  / \:\  \ /:/  / \:\/:/ /:/  / \:\~~\~~\/__/
#  \::/__/    \:\  /:/  /      |:/:/  /      |:/:/  /   \:\  /:/  /   \::/_/:/  /   \:\  \
#   \:\  \     \:\/:/  /       |::/  /       |::/  /     \:\/:/  /     \:\/:/  /     \:\  \
#    \:\__\     \::/  /        |:/  /        |:/  /       \::/  /       \::/  /       \:\__\
#     \/__/      \/__/         |/__/         |/__/         \/__/         \/__/         \/__/
#
# FuzzGen - The Automatic Fuzzer Generator
#
#
#
# get_tests.sh
#
# Test programs for libraries are very beneficial as they demonstrate how the library should be
# used. However under normal build, test programs are not compiled, so we can't emit their IR.
# This script comes to solve this problem by searching for test directories (that have a valid
# Android makefile), compiling them, obtaining the bitcode files, converting them into
# human-readable IR and moving them to a safe directory.
#
# Note that we should make the appropriate changes to the clang and clang++ binaries in order to
# emit the bitcode (see README for more details).
#
# -------------------------------------------------------------------------------------------------
TARGET_DEVICE="aosp_walleye-userdebug"
NJOBS=16
TEST_DIR="$HOME/GIANT/test_dirs"



# -------------------------------------------------------------------------------------------------
# Hook Ctrl+C signals and safely terminate script.
#
function halt() {
    msg "Execution cancelled by user!"
    exit 0
}



# -------------------------------------------------------------------------------------------------
# Display a message.
#
msg() {
    GREEN='\033[01;32m'                         # bold green
    NC='\033[0m'                                # no color
    echo -e "${GREEN}[INFO]${NC} $1"
}



# -------------------------------------------------------------------------------------------------
# Display an error.
#
error() {
    RED='\033[01;31m'                           # bold red
    NC='\033[0m'                                # no color
    echo -e "${RED}[ERROR]${NC} $1"
}



# -------------------------------------------------------------------------------------------------
# Main code
#

# before anything, hook Ctrl+C signals
trap halt INT

# The only argument here, is the path to the Android source tree
if [ $# -ne 1 ]; then
    echo "Usage: $0 \$ANDROID_DIR (full path)"
    exit
fi

msg "Starting 'get_tests' tool (FuzzGen auxiliary) at $(date)"

ANDROID_SOURCE=$1

# if path ends with a '/', drop it
if [ ${ANDROID_SOURCE:${#ANDROID_SOURCE}-1:1} = "/" ]; then
    msg "Dropping last '/' from path..."
    ANDROID_SOURCE=${ANDROID_SOURCE::${#ANDROID_SOURCE}-1}
fi

# initialize build environment
cd "$ANDROID_SOURCE" && source "build/envsetup.sh"  &> /dev/null \
                   && lunch $TARGET_DEVICE &> /dev/null

if [ $? -ne 0 ]; then
    error "Cannot initialize build environment (Are you sure '$1' is correct?)"
    exit 0
fi

mkdir "$TEST_DIR" 2> /dev/null


msg "Searching for test directories in $ANDROID_SOURCE ..."

# search the whole Android source tree for test directories
find "$ANDROID_SOURCE" -type d -name "test" -print0 \
| while IFS= read -r -d '' dir 
do    
    # check if an makefile (.mk or .bp) is present
    if [[ ! -f "$dir/Android.mk" && ! -f "$dir/Android.bp" ]]; then
        error "Make file not found. Discarding '$dir'"
        continue
    fi


    # jump into this directory and (try to) compile it
    cd "$dir"

    # in case that it's already built, clean directory first
    msg "Cleaning any previous builds in'${dir:${#ANDROID_SOURCE}+1}' ..."
    mm clean #&> /dev/null

    msg "Compiling test directory '${dir:${#ANDROID_SOURCE}+1}' ..."
    mm -j$NJOBS #&> /dev/null

    if [ $? -eq 0 ]
    then
        msg "Compilation succeeded!"

        # create test directory
        mkdir --parents "$TEST_DIR/${dir:${#ANDROID_SOURCE}+1}"


        # obtain the LTO
        msg "  Obtaining LTO ..."

        # save current directory
        PWD=$(pwd)
        cd "$ANDROID_SOURCE"
        # llvm link needs to get *.bc files from the same directory
        llvm-link *.bc -o "$TEST_DIR/${dir:${#ANDROID_SOURCE}+1}_lto.bc"
        llvm-dis "$TEST_DIR/${dir:${#ANDROID_SOURCE}+1}_lto.bc"

        # return back
        cd "$PWD"

        # compilation was OK. Now cast the bitcode files to human readable .ll
        for bitcode in $(find $ANDROID_SOURCE -maxdepth 1 -name "*.bc")
        do
            bc="${bitcode:${#ANDROID_SOURCE}+1}"
            ll="${bitcode:0:${#bitcode}-3}.ll"

            msg "  Converting '$bc' to '${bc:0:${#bc}-3}.ll' ..."

            # disassemble bitcode file
            llvm-dis "$bitcode"

            # move file to the target location
            mv "$ll" "$TEST_DIR/${dir:${#ANDROID_SOURCE}+1}"
        done
     
    else
        error "Compilation failed. Much sad. :("
    fi

    # remove leftovers
    rm "$ANDROID_SOURCE/*.i"  2> /dev/null
    rm "$ANDROID_SOURCE/*.ii" 2> /dev/null
    rm "$ANDROID_SOURCE/*.bc" 2> /dev/null
done


msg "Program finished!"
msg "Bye bye :)"

exit

# -------------------------------------------------------------------------------------------------
