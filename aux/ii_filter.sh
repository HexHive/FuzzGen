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
# ii_filter.sh
#
# This script scans the directory with the intermediate files and deletes each file that does not
# have an equivalent bitcode file. Altough bc_filter.sh copies the correct bitcode files, it does
# not do this for *.i and *.ii files (my bad). So I ended up with the correct set of bitcode files,
# but with an overapproximation of intermediate files.
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
# Display an error.
#
error() {
    RED='\033[01;31m'                           # bold red
    NC='\033[0m'                                # no color
    echo -e "${RED}[ERROR]${NC} $1"
}



# -------------------------------------------------------------------------------------------------
# Filter out *.i and *.ii files that do not have an equivalent bitcode file.
#
filter() {
    BC_DIR=$1                                       # directory with bitcode files
    II_DIR=$2                                       # directory with *.i and *.ii files
    WILDCARD=$3                                     # wildcard pattern to search for files
    EXTLEN=$4                                       # length of the extension

    # search in Android root (only in top level directory) for bitcode files
    find $II_DIR -maxdepth 1 -type f -name $WILDCARD -print0 \
    | while IFS= read -r -d '' file 
    do    
        # isolate file name
        FILENAME=${file:${#II_DIR}+1}
        FILENAME=${file##*/}

        # drop the extension '.i' (or '.ii' depends on $EXTLEN)
        PURENAME=${FILENAME::EXTLEN} 
        
        # check if filename exists somewhere in the bitcode directory
        if [[ -n $(find "$BC_DIR" -type f -name "$PURENAME\.tmp.bc") ]]
        then
            msg "$file has a bitcode file :)"
        else
            error "$file does not have a bitcode file :("

            rm "$file"            
        fi
    done
}



# -------------------------------------------------------------------------------------------------
# Main code
#

# before anything, hook Ctrl+C signals
trap halt INT

# Our arguments here are the path to the Android source tree and the output directory
if [ $# -ne 2 ]; then
    echo "Usage: $0 \$BC_DIR \$II_DIR (full paths)"
    exit
fi

msg "Starting 'ii_filter' tool (FuzzGen auxiliary) at $(date)"

# TODO: Use realpath to make all paths absolute
BC_DIR=$1
II_DIR=$2


# filter out *.i files
msg "Filtering out .i files from $II_DIR ..."
filter $BC_DIR $II_DIR '*.i' -2 

# filter out *.ii files
msg "Filtering out .ii files from $II_DIR ..."
filter $BC_DIR $II_DIR '*.ii' -3


msg "Program finished!"
msg "Bye bye :)"

exit

# -------------------------------------------------------------------------------------------------
