#!/usr/bin/env python2
# -------------------------------------------------------------------------------------------------
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
# plot_coverage.py:
#
# Collect the code coverage information that was created during fuzzing and visualize it. This tool
# supports 2 ways to collect coverage:
#
# 1) From libfuzzer stdout. When a new area of the program is explored, libfuzzer prints a line
# starting with the "NEW" keyword and displays the new coverage. We prepend a timestamp before
# each line and we save it into a file for later processing.
#        
#   ./libpng_fuzzer -close_fd_mask=2 CORPUS 2>&1 | \
#       while IFS= read -r line; do printf '[%s] %s\n' "$(date '+%s')" "$line"; done | \
#       tee log.txt
#
# 2) From AFL input files in queue/ or libfuzzer input files in corpus/. Each time a new path is 
# explored, a new input file is created. We leverage the timestamp (when file created) and we run
# the program with this given input under an instrumentation framework (DynamoRIO) to measure the
# exact code coverage. 
#
# This tool also calculates the aggregate coverage. Each time that we run the instrumentation we
# log all the distinct basic blocks that were executed and we aggregate them. To do this it is
# required to disable ASLR:
#
#       echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
#
# -------------------------------------------------------------------------------------------------
import sys
import os
import subprocess
import re
import datetime
import time
import argparse
import matplotlib.pyplot as plt
import logging
import angr



# -----------------------------------------------------------------------------
# Configuration parameters
# -----------------------------------------------------------------------------
DR_BUILD_DIR     = "/home/ispo/fuzzing/dynamorio/build"
MAX_TIMEOUT      = 12
TIMEOUT_INTERVAL = 1

# do not modify these
MAX_TIMEOUT_SEC = MAX_TIMEOUT * 3600
DR_PATH   = DR_BUILD_DIR + "/bin64/drrun"
DR_CLIENT = DR_BUILD_DIR + "/api/bin/libblkcov.so"
aggr_cov  = set()


# -------------------------------------------------------------------------------------------------
# Parse the libfuzzer output. Please note that the coverage here is the *total* (from all loaded
# modules). If there's a single module we're all good. Otherwise this introduces some small
# imprecision, but that's not a big deal as libc and other libs have very low coverage. 
#
def parse_libfuzzer_output(filename):
    coverage = []

    with open(filename, "r") as file:               # read libfuzzer output
        for line in file:                           # and process it line by line
            tokens = line.split()                   # split line into tokens
                        
            # We're interested in NEW lines (when code coverage is modified)
            # A line looks like this:
            #   [1547512566] #33        NEW    cov: 83 ft: 93 corp: 9/48Kb exec/s: 0 rss: 40Mb
            #   L: 1395/30486 MS: 1 InsertRepeatedBytes-
            #
            if len(tokens) == 20 and tokens[2] == 'NEW':
                timestamp = int(tokens[0][1:-1])
                cov_blks  = int(tokens[4])

                coverage.append((timestamp, cov_blks))

    # find minimum timestamp and subtract it from every element
    min_ts, _  = min(coverage, key=lambda x: x[0])
    coverage   = map(lambda x: (x[0] - min_ts, x[1]),  coverage)
    _, max_cov = coverage[-1]

    # add 2 more element to make beautiful plots
    coverage = [(0, 0)] + coverage + [(MAX_TIMEOUT_SEC, max_cov)]

    return zip(*coverage)



# -------------------------------------------------------------------------------------------------
# Find all input files created during fuzzing.
#
def find_input_files(input_dir):
    # get all input files and their timestamps
    files    = os.listdir(input_dir)
    inp_pair = [(os.path.getctime(input_dir + '/' + file), file) for file in files]
    
    # find minimum timestamp and subtract it from every element
    min_ts, _ = min(inp_pair, key=lambda x: x[0])
    inp_pair  = map(lambda x: (x[0] - min_ts, x[1]),  inp_pair)


    # sort files according to their timestamp
    inp_pair.sort(key=lambda x: x[0])

    return inp_pair



# -------------------------------------------------------------------------------------------------
# Get the total number of basic blocks in the fuzzer/shared library.
#
def get_total_blks(fuzzer):
    project = angr.Project(fuzzer, load_options={'auto_load_libs': False})

    print "[+] Generating Control Flow Graph (CFG). This may take a while ...."

    CFG = project.analyses.CFGFast()

    # normalize CFG (i.e. make sure that there are no overlapping basic blocks)
    CFG.normalize()                                 

    nnodes = len(CFG.graph.nodes())

    print "[+] Done. CFG has %d nodes." % nnodes

    return nnodes



# # -----------------------------------------------------------------------------------------------
# # DEPRECATED: Run an instrumentation in the program using a specific input to measure block
# # coverage on the shared library.
#
# def get_single_coverage(inp, prog, args, libso_name, method='arg'):
#     # build command to execute
#     dynrio = {
#         'arg'   : "%s -c %s -- %s %s"       % (DR_PATH, DR_CLIENT, prog, inp),
#         'stdin' : "cat %s | %s -c %s -- %s" % (inp, DR_PATH, DR_CLIENT, prog)
#     }[method]
#
#     # invoke a shell command to get the basic block coverage
#     pipe = subprocess.Popen(dynrio, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#
#     # output looks like this:
#     #
#     #       [+] Instrumentation finished. 0 blocks executed.
#     #       [+]    +----------------------------------+----------+
#     #       [+]    |           Module Name            |  Blocks  |
#     #       [+]    +----------------------------------+----------+
#     #       [+]    | ld-linux-x86-64.so.2             |     1432 |
#     #       [+]    | libc.so.6                        |      896 |
#     #       [+]    | libm.so.6                        |       46 |
#     #       [+]    | libpng16.so.16                   |      650 |
#     #       [+]    | libz.so.1                        |      450 |
#     #       [+]    | readpng                          |      101 |
#     #       [+]    +----------------------------------+----------+
#     #       [+]    | Total                            |     3575 |
#     #       [+]    +----------------------------------+----------+
#     #
#     libso_cov, total_cov = None, None
#
#     for line in pipe.stdout:
#         # When we split a line: ['[+]', '|', 'libpng16.so.16', '|', '648', '|']
#         if libso_name in line:            
#             libso_cov = int(line.split()[4])
#         elif 'Total' in line:
#             total_cov = int(line.split()[4])
#
#
#     if libso_cov == None or total_cov == None:
#         print "[!] Error. Can't get coverage. Instrumentation output:"
#         print pipe.stdout.readlines()
#
#     return libso_cov, total_cov



# -------------------------------------------------------------------------------------------------
# Run an instrumentation in the program using a specific input to measure the aggregate block
# coverage on the fuzzer/shared library.
#
def get_aggregate_coverage(fuzzer, input, args, module, ctr, method='arg'):
    global aggr_cov

    # build command to execute
    # TODO: add 'args'
    dynrio = {
        'arg'   : "%s -c %s -outfile 'blk_%d.cov' -- %s %s" % 
                            (DR_PATH, DR_CLIENT, ctr, fuzzer, input),
        'stdin' : "cat %s | %s -c %s -outfile 'blk_%d.cov' -- %s" % 
                            (input, DR_PATH, DR_CLIENT, ctr, fuzzer)
    }[method]


    # invoke a shell command to get the basic block coverage
    pipe = subprocess.Popen(dynrio, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # wait for instrumentation to finish
    pipe.wait()
    
    # check if execution was successful
    if pipe.returncode != 0:
        print '[-] Error! Dynamic instrumentation failed.'
        return None
        

    # we only care for the 'blk_xx.cov' file that was created
    with open("blk_%d.cov" % ctr, "r") as file:     # read block coverage output
        for line in file:                           # and process it line by line
            tokens = line.split()                   # split line into tokens
            
            # We're interested in @blkid lines
            # Lines look like this:
            #       @module libpng16.so.16  164
            #       @blkid  libpng16.so.16  0x00007ffff6bd9248
            #            
            if len(tokens) == 3 and tokens[0] == "@blkid":            
                if tokens[1] == module:
                    aggr_cov.add(tokens[2])


    # return aggregate coverage
    return len(aggr_cov)



# -------------------------------------------------------------------------------------------------
# Parse the command line arguments.
#
def parse_args():
    # create the parser object and the groups
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)

    group_l = parser.add_argument_group('Libfuzzer Mode (Edge Coverage)')
    group_d = parser.add_argument_group('Dynamic Instrumentation Mode (Basic Block Coverage)')


    # -------------------------------------------------------------------------
    # General arguments
    # -------------------------------------------------------------------------
    parser.add_argument(
        "--total-coverage",
        help     = "Total coverage of the library",
        action   = 'store',
        dest     = 'total_cov',
    )

    parser.add_argument(
        "--output",
        help     = "Output file with the generated figure",
        action   = 'store',
        dest     = 'output',
        required = True
    )
    
    # -------------------------------------------------------------------------
    # LibFuzzer mode
    # -------------------------------------------------------------------------
    group_l.add_argument(
        "--libfuzzer",
        help     = "Libfuzzer log (as generated from libfuzzer_run.sh) from the manual (ispo)"
                   "and the auto (FuzzGen) fuzzers",
        action   = 'append',
        nargs    = 2,
        metavar  = ('ispo-fuzzer','fuzzgen-fuzzer'),
        required = False
    )

    # -------------------------------------------------------------------------
    # Dynamic Instrumentation mode
    # -------------------------------------------------------------------------
    group_d.add_argument(
        "--fuzzer",
        help     = "Fuzzer binary to run",
        action   = 'store',
        dest     = 'fuzzer',
        required = False
    )

    group_d.add_argument(
        "--input-dir",
        help     = "Input directory with all generated test cases",
        action   = 'store',
        dest     = 'input_dir',
        required = False
    )

    group_d.add_argument(
        "--module",
        help     = "Module name (either library *.so file or fuzzer binary",
        action   = 'store',
        dest     = 'module',
        required = False
    )

    group_d.add_argument(
        "--method",
        help     = "How to pass input file to the fuzzer (through stdin or command line)",
        choices  = ['arg', 'stdin'],
        action   = 'store',
        dest     = 'method',
        required = False,
    )

    group_d.add_argument(
        "--args",
        help     = "Addtional command line arguments to the fuzzer",
        action   = 'store',
        dest     = 'args',
        required = False
    )


    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)


    return parser.parse_args()                      # do the parsing (+ error handling)



# -------------------------------------------------------------------------------------------------
# This is the main function. 
#
if __name__ == '__main__':

    args = parse_args()                             # parse arguments
    now = datetime.datetime.now()

    print "[+] Starting 'plot_coverage' tool (FuzzGen auxiliary) at %s" % \
            now.strftime("%d/%m/%Y %H:%M")


    # -------------------------------------------------------------------------
    # Mode #1: Plot coverage from libFuzzer output
    # -------------------------------------------------------------------------
    if args.libfuzzer and args.total_cov:
        total_cov = args.total_cov

        print "[+] Operating on libFuzzer mode."

        # get coverage from manual fuzzer
        timestamp, coverage = parse_libfuzzer_output(args.libfuzzer[0][0])

        # get coverage from FuzzGen fuzzer
        timestamp2, coverage2 = parse_libfuzzer_output(args.libfuzzer[0][1])

        # plot coverage curves
        plt.plot(timestamp,  coverage,  label='Old Fuzzer')
        plt.plot(timestamp2, coverage2, label='New Fuzzer')
        plt.ylabel('Code Coverage (in edges)')


    # -------------------------------------------------------------------------
    # Mode #2: Plot coverage from libFuzzer output
    # -------------------------------------------------------------------------
    elif args.fuzzer and args.input_dir and args.module and args.method:
        print "[+] Operating on Dynamic Instrumentation mode."

        # check if total coverage is provided
        if args.total_cov:
            total_cov = args.total_cov
        else:
            print "[+] Total coverage is not provided. Calculating it from CFG."

            logging.getLogger('angr').setLevel('CRITICAL')
            total_cov = get_total_blks(args.fuzzer)


        lib_cov = []
        ctr     = 0

        # get coverage for each input file
        input_files = find_input_files(args.input_dir)
        
        for timestamp, inp_file in input_files:
            
            # instrument basic block coverage
            coverage = get_aggregate_coverage(
                            args.fuzzer, 
                            args.input_dir + '/' + inp_file, 
                            '', 
                            args.module, 
                            ctr, 
                            args.method
                        )

            print "[+] (%d/%d) Coverage Info: Time = %12f, Coverage = %d (File: %s)" % \
                        (ctr, len(input_files), timestamp, coverage, inp_file)

            lib_cov.append((timestamp, coverage))
            ctr += 1



        # add 2 more element to make beautiful plots
        lib_cov = [(0,0)] + lib_cov + [(MAX_TIMEOUT_SEC, coverage)]
        timestamp, coverage = zip(*lib_cov)

        # plot coverage curves
        plt.plot(timestamp,  coverage,  label='LibFuzzer')
        plt.ylabel('Code Coverage (in basic blocks)')


    # -------------------------------------------------------------------------
    # Invalid Mode
    # -------------------------------------------------------------------------
    else:
        print "[-] Error! Invalid mode. Please check command line options.";
        exit()


    # plot the total coverage (it's a straight line, so 2 points are enough)
    coverage3, timestamp3 = [int(total_cov)]*2, [0, MAX_TIMEOUT_SEC]
    plt.plot(timestamp3, coverage3, label='Total Coverage')        

    # all good. Finalize plot
    plt.grid()                                      # add a grid
    plt.title(args.output)                          # add title
    plt.legend()                                    # add legends
    plt.xlabel('Time (in hours)')                   # add labels
    plt.axis([-500, MAX_TIMEOUT_SEC, 0, int(total_cov)+500])   # adjust axes

    # adjust ticks (cast seconds into hours)
    plt.xticks( [i*3600     for i in range(0, MAX_TIMEOUT+1, TIMEOUT_INTERVAL)], 
                ['%dhr' % i for i in range(0, MAX_TIMEOUT+1, TIMEOUT_INTERVAL)])

    
    print "[+] Done. Figure saved as '%s.pdf' " % args.output

    plt.savefig(args.output + '.pdf', format='pdf') # save figure
    plt.show()                                      # and display it

    print "[+] Program finished!"
    print "[+] Bye bye :)"


# -------------------------------------------------------------------------------------------------
