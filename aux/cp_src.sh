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
# cp_src.sh
#
# Source files are required to identify external modules that use API functions. However AOSP is
# huge and contains a lot of other files thus making the search extremely slow. This script
# isolates all source files (*.c *.cpp *.h *.hpp) from AOSP in a new, clean directory. Perfroming
# searches in this directory is must faster.
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

# Our arguments here are the path to the Android source tree and the output directory
if [ $# -ne 2 ]; then
    echo "Usage: $0 \$ANDROID_DIR \$OUTPUT_DIR (full paths)"
    exit
fi

msg "Starting 'cp_src' tool (FuzzGen auxiliary) at $(date)"

ANDROID_SOURCE=$1
OUTPUT_DIR=$2

# if path ends with a '/', drop it
if [ ${ANDROID_SOURCE:${#ANDROID_SOURCE}-1:1} = "/" ]; then
    msg "Dropping last '/' from path..."
    ANDROID_SOURCE=${ANDROID_SOURCE::${#ANDROID_SOURCE}-1}
fi

if [ ${OUTPUT_DIR:${#OUTPUT_DIR}-1:1} = "/" ]; then
    msg "Dropping last '/' from output directory..."
    OUTPUT_DIR=${OUTPUT_DIR::${#OUTPUT_DIR}-1}
fi

# create output directory (ignore errors if already exists)
mkdir "$OUTPUT_DIR" 2> /dev/null


msg "Searching for source files in $ANDROID_SOURCE ..."

# search the whole Android source tree for source files
find $ANDROID_SOURCE -type f -regex '.*\.\(c\|cpp\|h\|hpp\)$' -print0 \
| while IFS= read -r -d '' file 
do
    # drop $ANDROID_SOURCE from path
    PUREPATH=${file:${#ANDROID_SOURCE}+1}

    # get the actual filename
    FILENAME=${file##*/}

    # get the subpath ($PUREPATH without $FILENAME)
    SUBPATH=${PUREPATH:0:${#PUREPATH}-${#FILENAME}}

    msg "Copying '$PUREPATH'"

    # create all subdirectories first
    mkdir --parents "$OUTPUT_DIR/$SUBPATH"

    # do the actual file copy 
    cp --force "$file" "$OUTPUT_DIR/$PUREPATH" 2> /dev/null
done


msg "Program finished!"
msg "Bye bye :)"

exit

# -------------------------------------------------------------------------------------------------
