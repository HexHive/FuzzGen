#!/usr/bin/env python2
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
# consumer_rank.py
#
# A library can have a lot of different consumers. If FuzzGen includes all of them in its analysis
# the generated fuzzers will be huge, cumbersome and extremely hard to verify their correctness.
# To deal with this issue, we deterministically select K consumers to include them in the analysis.
# Each consumer is assigned a "score" and at the end the consumers with the highest score are
# selected.
#
# There are several metrics to use but the most likely to use is the ratio:
#       # of distinct API calls / lines of pure code 
#
#
# The intuition behind this metric, is to select "library oriented" consumers. That is, if a
# consumer contains a lot of code that is not relevant with the library, then it's probably not
# very focused on the library.
#
# There are 2 types of library consumers: internal (which are small programs used for testing the 
# library and come along with library's source code) and external (which are standalone debian
# packages in source repository and utilize the library). We can collect all these packages by
# searching for reverse dependencies: `apt-cache rdepends $pkg` and downloading the source code 
# for each package:
#
#       for dep in $(apt-cache rdepends libpng16-16) 
#       do 
#           apt-get source $dep; 
#       done
#
# For debian packages we "merge" the source code from all files and we treat it as a monolithic
# source code. 
#
# -------------------------------------------------------------------------------------------------
import sys
import os
import subprocess
import re
import datetime
import argparse



# -------------------------------------------------------------------------------------------------
# Find all source files (*.c/*.cpp) contained in the library.
#
def find_src_files(libroot):
    src_files = []

    for path, dirs, files in os.walk(libroot):
        for filename in files:
            if filename.endswith(".c")  or filename.endswith(".cpp") or \
               filename.endswith(".h")  or filename.endswith(".hpp") or \
               filename.endswith(".cc"):
                    src_files.append(os.path.join(path, filename))

    return src_files



# -------------------------------------------------------------------------------------------------
# Get the source code of a file (with or without the comments and blank lines)
#
def get_src_code(filename, drop_comments=True):
    src_code = []


    if drop_comments:
        # use gcc to remove fluff from the code
        # UPDATE: sometimes gcc hangs, so add a small timeout
        cmd = "timeout 4s gcc -fpreprocessed -dD -E -P " + filename
    else:
        # just print the file
        cmd = "cat " + filename
    
    # invoke shell command to get the source code in stdout
    pipe = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


    for line in pipe.stdout:
        src_code.append(line)

    return src_code



# -------------------------------------------------------------------------------------------------
# Check if a source file contains a main() or an LLVMFuzzerTestOneInput() function. We can do this
# through grep:
#       grep --quiet "\bmain\b[ ]*(" "$file"
#
def has_main(src_code):
    for line in src_code:
        if re.search("int[ ]*main[ ]*\(", line) or \
           re.search("[ ]*LLVMFuzzerTestOneInput[ ]*\(", line) or \
           re.search("[ ]*regression_test[ ]*\(", line):
                return True

    return False



# -------------------------------------------------------------------------------------------------
# Count the total number of (distinct) API calls in the source code.
#
def count_api_calls(src_code, api_list):
    calls = []

    # do a naive O(N^2) search
    for line in src_code:                
        for api in api_list:
            if api in line:
                calls.append(api)


    # return the total number of API calls and the total number of distinct API calls
    return len(calls), len(set(calls))



# -------------------------------------------------------------------------------------------------
# Parse the command line arguments.
#
def parse_args():
    # create the parser object and the groups
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument(
        "--library",
        help     = "Library's root directory",
        action   = 'store',
        dest     = 'lib',
        required = False
    )

    parser.add_argument(
        "--pkg-dir",
        help     = "Packages root directory",
        action   = 'store',
        dest     = 'pkg',
        required = False
    )

    parser.add_argument(
        "--api",
        help     = "API file (a function per line)",
        action   = 'store',
        dest     = 'api',
        required = True
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

    print "[+] Starting 'consumer_rank' tool (FuzzGen auxiliary) at %s" % \
            now.strftime("%d/%m/%Y %H:%M")

    try:
        # get API calls
        api_list = [line.rstrip('\n') for line in open(args.api)]; 
        api_list = filter(None, api_list)           # drop empty lines

    except IOError:
        print "[!] Error. Invalid filename '" + args.api + "'"
        exit()


    consumers = []                                  # place all consumers here
    maxlen    = 10                                  # just initialize


    # -------------------------------------------------------------------------
    # Part #1: Rank consumers inside the library
    # -------------------------------------------------------------------------
    if args.lib:
        src_files = find_src_files(args.lib)        # find all source files 

        if len(src_files) < 1:
            print "[!] Error. No source files found."
            exit()


        # get length of the longest filename (or debian package: max(src_files, key=len))
        maxlen = len(max(src_files, key=len))
        cnt    = 1   

        for file in src_files:
            print "[+] (%d/%d) Parsing '%s'" % (cnt, len(src_files), file),

            src_cmt  = get_src_code(file, False)
            src_pure = get_src_code(file, True)
            
            if has_main(src_pure):
                print '(main found!)',

                API, dAPI = count_api_calls(src_pure, api_list)

                consumers.append(('lib ', file.ljust(maxlen), len(src_cmt), len(src_pure), 
                                  API, dAPI, float(API)/len(src_pure), float(dAPI)/len(src_pure)))
            
            cnt += 1

            print


    # -------------------------------------------------------------------------
    # Part #2: Rank consumers from Debian packages
    # -------------------------------------------------------------------------
    if args.pkg:
        dpkgs = os.walk(args.pkg).next()[1]         # get all debian packages
        cnt   = 1                                   # counter

        # for each debian package
        for dirent in dpkgs:
            # find all source files 
            src_files = find_src_files(args.pkg + "/" + dirent)

            print "[+] (%d/%d) Parsing '%s' package (%d source files)" % \
                    (cnt, len(dpkgs), dirent, len(src_files))


            if len(src_files) < 1:
                cnt += 1            
                continue

            src_cmt, src_pure = [], []

            # accumulate all source code in the package
            for file in src_files:
                src_cmt  += get_src_code(file, False)
                src_pure += get_src_code(file, True)
                

            # count API calls
            API, dAPI = count_api_calls(src_pure, api_list)


            consumers.append(('pkg ', dirent.ljust(maxlen), len(src_cmt), len(src_pure),
                              API, dAPI, float(API)/len(src_pure), float(dAPI)/len(src_pure)))
            
            cnt += 1


    # -------------------------------------------------------------------------
    # Rank consumers (use the last columnt to sort) and display results
    # -------------------------------------------------------------------------
    consumers.sort(key=lambda tup: tup[7], reverse=True)

    print 
    print "Final rank:"
    print "+------+-"         +"-"*maxlen    +"-+--------+--------+------+------+-------+-------+"
    print "| Type | Consumer "+" "*(maxlen-8)+ "| LoC    | LoPC   | API  | dAPI | R1    | R2    |"
    print "+------+-"         +"-"*maxlen    +"-+--------+--------+------+------+-------+-------+"

    for consumer in consumers:
        print "| %s | %s | %6d | %6d | %4d | %4d | %.3f | %.3f |" % consumer


    print "+------+-" + "-"*maxlen + "-+--------+--------+------+------+-------+-------+"
    print
    print "[+] LoC  = Lines of Code"
    print "[+] LoPC = Lines of Pure Code (without comments and blank lines)"
    print "[+] API  = Number of API calls"
    print "[+] dAPI = Number of distinct API calls"
    print "[+] R1   = API / LoPC ratio"
    print "[+] R2   = dAPI / LoPC ratio"


    print "[+] Program finished!"
    print "[+] Bye bye :)"

# -------------------------------------------------------------------------------------------------
