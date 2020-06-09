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
# bc_filter.sh
#
# When the clang/clang++ emits the LLVM IR files from some library, it also emits the LLVM IR
# from library's dependencies (/bionic etc.). LTOing all these files, makes analysis cumbersome
# and screws up the search for external modules.
#
# This script filters out generated bitcode files. For each file it looks whether its name exists
# under the library's source directory and if not it discards it.
#
# An alternative approach is to llvm-dis each file and check the "source_filename" at the
# beginning.
#
# -------------------------------------------------------------------------------------------------



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
# Main code
#

# before anything, hook Ctrl+C signals
trap halt INT

# Our arguments here are the path to the Android source tree, the path to the library source
# and the output directory
if [ $# -ne 3 ]; then
    echo "Usage: $0 \$ANDROID_ROOT \$LIB_DIR \$OUTPUT_DIR (full paths)"
    exit
fi

msg "Starting 'bc_filter' tool (FuzzGen auxiliary) at $(date)"


# TODO: Use realpath to make all paths absolute
ANDROID_ROOT=$1
LIB_DIR=$2
OUTPUT_DIR=$3


msg "Searching for bitcode files in $ANDROID_ROOT ..."

# create output directory (ignore errors if already exists)
mkdir "$OUTPUT_DIR" 2> /dev/null

# search in Android root (only in top level directory) for bitcode files
find $ANDROID_ROOT -maxdepth 1 -type f -name '*.bc' -print0 \
| while IFS= read -r -d '' file 
do    
    # isolate file name
    FILENAME=${file:${#ANDROID_ROOT}+1}
    FILENAME=${file##*/}

    # drop the extension '.tmp.bc'
    PURENAME=${FILENAME::-3} 
    PURENAME=${PURENAME::-4}

    # check if filename exists somewhere in the library source
    if [[ -n $(find "$ANDROID_ROOT/$LIB_DIR" -type f -regex ".*/$PURENAME\.\(c\|cpp\|h\|hpp\)\$") ]]
    then
        msg "$FILENAME is part of the library!"

        # fopy bitcode file to a safe location
        cp "$file" "$OUTPUT_DIR/"
    fi
done


msg "Program finished!"
msg "Bye bye :)"

exit

# -------------------------------------------------------------------------------------------------
