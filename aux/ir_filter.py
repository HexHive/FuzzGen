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
# ir_ filter.py
#
# This script filters out the IR files that are part of the library. When we compile a library,
# we may also compile test files or other external modules and dump the LLVM IR for these files.
# This script uses a robots.txt-like language to create a set of rules and filter IR files
# accordingly. 
# 
# User gives a *.policy file to the script that instructs whics directories should be included
# (whitelist) or should be excluded (blacklist) from the source tree for the library.
#
# -------------------------------------------------------------------------------------------------
import sys
import os
import subprocess
import re
import datetime
import argparse



# -------------------------------------------------------------------------------------------------
# Load a policy file.
#
def load_policy(policy_file):
    # We may have more complicated policies in the future, so we keep it as a dictionary.
    policy = {
        'Allow': [],
        'Disallow': []
    }

    print "[+] Loading policy file '%s' ..." % policy_file

    try:
        with open(policy_file, "r") as file:        # read policy file
            for line in file:                       # and process it line by line

                # ignore comments
                if re.search(r'^\s*#', line) is not None:
                    continue

                # match default policy
                match_default = re.search(r'^\s*Default-policy: (Allow|Disallow)', line)
                if match_default is not None:
                    policy['Default-policy'] = match_default.group(1)
                    print "[+]\tParsing rule: 'Default-policy: %s'" % match_default.group(1)

                # match "allow" rules
                match_allow = re.search(r'^\s*Allow: (.+)', line)
                if match_allow is not None:                    
                    policy.setdefault('Allow', []).append(match_allow.group(1))
                    print "[+]\tParsing rule: 'Allow: %s'" % match_allow.group(1)

                # match "disallow" rules
                match_disallow = re.search(r'^\s*Disallow: (.+)', line)
                if match_disallow is not None:
                    policy.setdefault('Disallow', []).append(match_disallow.group(1))
                    print "[+]\tParsing rule: 'Disallow: %s'" % match_disallow.group(1)

    except IOError, ex:
        print "[!] An exception was raised: '%s'" % str(ex)
        return None


    if 'Default-policy' not in policy:
        print "[!] Parsing error: 'Default-policy' is missing"
        return None        

    return policy



# -------------------------------------------------------------------------------------------------
# Check if a given directory is allowed according to the policy.
#
def dir_is_allowed(path, policy):
    # Check allow rules.
    for rule in policy['Allow']:
        if path.startswith(rule):
            print "[+] Rule match. Allow '%s'" % path
            return True

    # Check dis-allow rules.
    for rule in policy['Disallow']:
        if path.startswith(rule):
            print "[+] Rule match. Disallow '%s'" % path
            return False

    # Path not found in any rules. Check the default policy.
    if policy['Default-policy'] == 'Allow':
        print "[+] Rule match. Default-policy (allow) for '%s'" % path
        return True
    else:
        print "[+] Rule match. Default-policy (disallow) for '%s'" % path
        return False



# -------------------------------------------------------------------------------------------------
# Drop all extensions from a file name. Example: '/a/b/c/d.e.f.g' returns '/a/b/c/d'
#
def drop_extension(file):
    base_name = os.path.splitext(file)[0]
    
    while base_name.find('.') >= 0:
        base_name = os.path.splitext(base_name)[0]
    return base_name



# -------------------------------------------------------------------------------------------------
# Find all LLVM IR files that match to the policy.
#
def find_ir_files(policy, libroot, output):
    print "[+] Search source tree at '%s' for allowed IR files ..." % libroot

    # recursively search for all files and directories
    for path, dirs, files in os.walk(libroot):
        
        subpath = path[len(os.path.abspath(libroot)):] + '/'
        
       # print 'xx', subpath
        
        # check if directory is allowed or not according to the policy
        if dir_is_allowed(subpath, policy):
            for file in files:

                # ignore hidden files and IR files themselves
                if file.endswith('.c') or file.endswith('.h') or \
                   file.endswith('.cpp') or file.endswith('.hpp'):

                    # Example: vp8_decrypt_test.cc
                    # IR: vp8_decrypt_test.tmp.bc
                    base_name = drop_extension(file)
                    ir_file = base_name + ".tmp.bc"
                    ir_path = os.path.join(libroot, ir_file)

                    if os.path.exists(ir_path):
                        print "[+] Copying file '%s' to '%s' ..." % (ir_file,
                                                                     os.path.join(output, ir_file))

                        src = os.path.join(libroot, ir_file)
                        dst = os.path.join(os.path.abspath(output), ir_file)
                        os.popen("cp '%s' '%s'" % (src, dst))
    return 



# -------------------------------------------------------------------------------------------------
# Parse the command line arguments.
#
def parse_args():
    # create the parser object and the groups
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument(
        'policy',
        help    = 'A text file that contains the policy desired',
        action  = 'store',
        default = None,

    )

    parser.add_argument(
        'library',
        help    = 'A path to the library',
        action  = 'store',
        default = None,

    )

    parser.add_argument(
        'output',
        help    = 'An output directory to store all files',
        action  = 'store',
        default = None,
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

    print "[+] Starting 'ir_filter' tool (FuzzGen auxiliary) at %s" % \
            now.strftime("%d/%m/%Y %H:%M")


    policy = load_policy(args.policy)
    if not policy:
        print "[!] Error cannot parse policy. Abort."
        exit()


    find_ir_files(policy, args.library, args.output)


    print "[+] Program finished!"
    print "[+] Bye bye :)"

# -------------------------------------------------------------------------------------------------