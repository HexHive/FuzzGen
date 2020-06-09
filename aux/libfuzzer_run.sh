#!/bin/sh
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
# libfuzzer_run.sh
#
# A wrapper around libFuzzer to properly run it on an Android device.
#
# -------------------------------------------------------------------------------------------------



# -------------------------------------------------------------------------------------------------
# Display a message.
#
msg() {
    GREEN='\033[01;32m'                         # bold green
    NC='\033[0m'                                # no color
    echo -e "${GREEN}[INFO]${NC} $1"
}



# -------------------------------------------------------------------------------------------------
# Hook Ctrl+C signals and safely terminate script.
#
function halt() {
    echo
    msg "Execution cancelled by user or alarm triggered!"
    exit 0
}



# -------------------------------------------------------------------------------------------------
# Wait for a while and then send a SIGTERM to the parent process.
#
function alarm {
    sleep $TIMEOUT
    
    echo "Sending a SIGTERM to the parent ($1)"

    # Send SIGTERM to the group (the dash before $1 is very important)
    kill -INT -$1
    exit 0
}



# -------------------------------------------------------------------------------------------------
# Main code
#
if [ $# -eq 3 ]; then
    LIBPATH=""

elif [ $# -eq 4 ]; then
    # export the new library path
    export LD_LIBRARY_PATH=$4

else
    echo "Usage: $0 \$LIBFUZZER_BINARY \$CORPUS \$LOGFILE [\$LIBPATH]"
    exit

fi

TIMEOUT=86400
LIBFUZZER_BINARY=$1
CORPUS=$2
LOGFILE=$3

msg "Starting 'libfuzzer_run' tool (FuzzGen auxiliary) at $(date)"

# before do anything, hook SIGINT signals
trap halt INT


PID=$$                                              # get process ID
alarm $PID &                                        # set the alarm
CHILD_PID=$!                                        # get child PID

msg "Process ID of the current process: $PID"
msg "Process ID of the child process: $CHILD_PID"

# initialize time variables
START=$(date '+%s')
CURRENT=0
ELAPSED=$TIMEOUT
COUNTER=1

# repeat until elapsed time becomes zero
until [ $ELAPSED -le 0 ]; 
do
    msg "Starting libfuzzer (#$COUNTER) at time $CURRENT ($ELAPSED seconds remaining)"


     # We want Ctrl+C to reach libfuzzer to dump the final coverage. Hence we ignore signals
     # on the other commands in the pipe through "trap '' INT;" command
     $LIBFUZZER_BINARY -close_fd_mask=2 -dump_coverage=1 -print_final_stats=1 "$CORPUS" 2>&1 | (
        trap '' INT; 

        while IFS= read -r line; 
        do 
            printf '[%s] %s\n' "$(date '+%s')" "$line"; 
        
        done | (
            trap '' INT; tee -a "$LOGFILE"
        )
    )

    # libfuzzer may take forever to run. That's find as we have set the alarm

    # udpate times
    CURRENT=$(( $(date '+%s') - $START ))    
    ELAPSED=$(( $TIMEOUT - $CURRENT ))

    msg "Libfuzzer finished after $CURRENT seconds."

    COUNTER=$(($COUNTER + 1))
done


# get final timestamp
CURRENT=$(( $(date '+%s') - $START ))    

msg "Program finished after $CURRENT seconds."
msg "Bye bye :)"

exit

# -------------------------------------------------------------------------------------------------
