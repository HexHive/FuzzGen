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
# wrap-c++.py:
#
# Exactly like wrap-c.py. The only different is that clang++ is invoked instead/
#
# -------------------------------------------------------------------------------------------------
import sys
import os
import subprocess
import re


compiler = '/usr/local/google/home/ispo/clang+llvm-7.0.0-x86_64-linux-gnu-ubuntu-16.04/bin/clang++'      # compiler to invoke


# -------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    argv = sys.argv[1:]                             # argv[0] is this python script

    # additional flags to get LLVM IR for each compiled module
    flags = ["-save-temps", "-S", "-emit-llvm", "-O0", "-m64",
             "-Wno-error", "-Wno-unused-command-line-argument"]


    r   = re.compile(".*\.(c|cpp)")
    src = list(filter(r.match, argv))


    print "[+] Compiling:", src

    # do this if there are enough arguments (prevent errors when you run ./configure)
    if len(argv) > 1 and len(src) > 0:
        # invoke compiler to get LLVM IR files
        try:
            subprocess.check_call([compiler] + argv + flags)

        except subprocess.CalledProcessError:
            print "[!] Error. Compiler faiure, but I don't care."

        except OSError:
            print "[!] Error. OS failure but I don't care."
        
    else:
        print '[+] Ingoring file. Arguments:', argv


    # invoke compiler for a 2nd time, to regularly compile the file
    os.execv(compiler, [compiler] + argv)


# -------------------------------------------------------------------------------------------------
