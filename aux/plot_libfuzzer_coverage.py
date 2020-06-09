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
# plot_libfuzzer_coverage.py:
#
# Collect the code coverage information from libfuzzer stderr and visualize it. When a new area of
# the program is explored, libfuzzer prints a line starting with the "NEW" keyword and displays the
# new coverage. We prepend a timestamp before each line and we save it into a file for later
# processing as follows:
#        
#   ./libpng_fuzzer -close_fd_mask=2 CORPUS 2>&1 | \
#       while IFS= read -r line; do printf '[%s] %s\n' "$(date '+%s')" "$line"; done | \
#       tee log.txt
#
# However this program does more than just visualizing the code coverage for a single file: It
# takes as input multiple files of fuzzing reports and performs a statistical testing on them. That
# is, it plots the *average* (and the best) code coverage from all runs.
# -------------------------------------------------------------------------------------------------
from __future__ import division
import sys
import os
import subprocess
import re
import datetime
import time
import argparse
import matplotlib.pyplot as plt
import math
import hashlib


# -------------------------------------------------------------------------------------------------
# Configuration parameters
# -------------------------------------------------------------------------------------------------
TOTAL_FUZZING_HOURS   = 24                          # set 24 hour runs
TOTAL_FUZZING_SECONDS = TOTAL_FUZZING_HOURS * 3600
MARGIN_SEC = 500

# time ticks (in hours) for x-axe. After 4 hours, coverage gets stabilized and updates are slower.
# We don't want to spend space for that, so we "compress time" and gave updates every 4 hours.
# NOTE: If you change this, make sure that it's consistent with PlotReports.add_plot()
TIME_TICKS = [0, 1, 2, 3, 4, 8, 12, 16, 20, 24]


# -------------------------------------------------------------------------------------------------
# Lambdas needed for the statistical testing
# -------------------------------------------------------------------------------------------------
roundup  = lambda x : int(math.ceil(x))              # round up a floating point
avg      = lambda x : roundup(sum(x) / len(x))       # find the average number of a list
avg_pure = lambda x : sum(x) / len(x)
std      = lambda x : math.sqrt(sum([(x_i - avg_pure(x))**2 for x_i in x]) / (len(x)))


# -------------------------------------------------------------------------------------------------
# This class contains all information regarding a fuzzing report.
# 
class FuzzReport(object):    
    # ---------------------------------------------------------------------------------------------
    # Class constructor.
    #
    def __init__(self, report_name, fuzzer_name):
        self.report_name  = report_name             # report name
        self.fuzzer_name  = fuzzer_name             # fuzzer name
        self.modules      = 0                       # number of loaded modules
        self.san_cov      = {}                      # sanitize coverage from other modules
        self.total_cov    = 0                       # total edge coverage
        self.extra_cov    = 0                       # additional coverage added by other modules
        self.max_cov      = 0                       # max edge coverage
        self.corpus_count = 0                       # number of seed corpus files
        self.avg_execs    = 0                       # average exec/s
        self.tot_execs    = 0                       # total exec/s
        self.coverage     = []                      # coverage array
        self.execs        = []                      # exec/s array
        self.time         = []                      # timestamp array
        self.restarts     = -1                      # how many times libfuzzer restarted


    # ---------------------------------------------------------------------------------------------
    # This function loads a libFuzzer report and extracts all meaningful information from it.
    #
    def load_report(self, filename):
        with open(filename, "r") as file:           # read libfuzzer output report
            for line in file:                       # and process it line by line

                # our lib_fuzzer.sh script restarts fuzzer when a crash is found. That is
                # we may have multiple lines that show e.g., the total coverage, so we add
                # print statements only at the end of the loop


                # -----------------------------------------------------------------------
                # Part #1: Extract total coverage. Examples:
                #  INFO: Loaded 1 modules (6193 guards): 6193 [0x55ba137000, 0x55ba13d0c4)
                #  INFO: Loaded 1 PC tables (12425 PCs): 12425 [0x64c2e1a090,0x64c2e4a920)
                #
                # Total Coverage is: 6193
                # -----------------------------------------------------------------------
                match_hdr = re.search(r'^\[[0-9]+\] INFO:[ \t]+Loaded ([0-9]+) (modules|PC tables)'
                                      r'[ \t]+\(([0-9]+) (guards|PCs)\)', line)

                if match_hdr is not None:
                    self.restarts += 1              # check how many times r

                    # match_hdr.group(2) is modules/PC tables
                    self.modules = int(match_hdr.group(1))
                    self.tot_cov = int(match_hdr.group(3))


                # -----------------------------------------------------------------------
                # Part #2: Extract the size of the initial corpus. Example
                #  INFO: seed corpus: files: 29201 min: 1b max: 11202628b total: 303254386b
                #
                # Initial corpus: 29201 files
                # -----------------------------------------------------------------------
                match_hdr2 = re.search(r'^\[[0-9]+\] INFO:[ \t]+seed corpus:[ \t]files: ([0-9]+)',
                                       line)

                if match_hdr2 is not None:
                    self.corpus_count = int(match_hdr2.group(1))


                # -----------------------------------------------------------------------
                # Part #3: Extract instant coverage. Examples:
                #  #45552 NEW cov: 2987 ft: 13354 corp: 2009/9806Kb exec/s: 337 rss: 92Mb
                #  #29202  INITED cov: 3989 ft: 12258 corp: 540/13534Kb lim: 4 exec/s: 1168
                #
                # Current iteration is 45552. Instant coverage is 2987 and executions per
                # second are 337.
                #
                # NOTE: In the older versions of libFuzzer, corpus length limit (lim:)
                # appears before 'exec/s'. This is not an issues as our regex can catch
                # this case as well.
                # -----------------------------------------------------------------------
                match_body = re.search(r'^\[([0-9]+)\] #([0-9]+)[ \t]+(INITED|NEW)[ \t]+cov: '
                                       r'([0-9]+) ft: [0-9]+ corp: .* exec/s: ([0-9]+)', line)

                if match_body is not None:
                    # match_body.group(3) is INITED/COV
                    timestamp = int(match_body.group(1))
                    coverage  = int(match_body.group(4))
                    execs     = int(match_body.group(5))

                    # Do the update only if coverage is larger
                    # This may happen when we restart and initial coverage is lower
                    if len(self.coverage) < 1 or self.coverage[-1] <= coverage:
                        self.time.append(timestamp)
                        self.coverage.append(coverage)
                        self.execs.append(execs)
        

                # -----------------------------------------------------------------------
                # Part #4: Extract average executions per second and total executions.
                # Example:
                #   stat::number_of_executed_units: 1028278
                #   stat::average_exec_per_sec:     28
                # -----------------------------------------------------------------------
                match_stat = re.search(r'^\[[0-9]+\] stat::number_of_executed_units:\s+([0-9]+)',
                                       line)

                if match_stat is not None:
                    self.tot_execs += int(match_stat.group(1))


                # -----------------------------------------------------------------------
                # Part #5: Extract maximum coverage from other modules (if any)
                # Example:
                #   SanitizerCoverage: ./libmpeg2_fuzzer_main-main.10358.sancov: 1072 PCs written
                #   SanitizerCoverage: ./libutils.so.10358.sancov: 19 PCs written
                # -----------------------------------------------------------------------                
                match_sancov = re.search(r'^\[[0-9]+\] SanitizerCoverage: '
                                         r'\.\/(.*)\.[0-9]+\.sancov: ([0-9]+) PCs written',
                                         line)

                if match_sancov is not None:
                    name = match_sancov.group(1)
                    cov  = int(match_sancov.group(2))

                    self.san_cov[name] = max(cov, self.san_cov.get(name, 0))
        

        self.max_cov = max(self.coverage)
        self.avg_execs = roundup(self.tot_execs / TOTAL_FUZZING_SECONDS)

        print '[+]\tTotal coverage   : %d'  % self.tot_cov
        print '[+]\tMaximum coverage : %d (%.2f%%)'  % (self.max_cov, self.max_cov/self.tot_cov*100)
        print '[+]\tTotal executions : %ld' % self.tot_execs
        print '[+]\tAverage exec/s   : %ld' % self.avg_execs
        print '[+]\tTotal restarts   : %d'  % self.restarts        
        print '[+]\tCorpus count     : %d files' % self.corpus_count
        
        if self.modules != 1:
            # Coverage represents the total coverage in all modules. When there
            # are >1 modules we do not know exactly what is the coverage in the
            # library that is being fuzzed which adds some imprecision to the
            # report.
            print '[!]\tFuzzer has %d modules. Coverage may be inaccurate' % self.modules

        print '[+]\tSanitize Coverage:'

        for name, cov in self.san_cov.iteritems():
            print "[+]    %24s: %d" % (name, cov)

            if self.fuzzer_name not in name:
                self.extra_cov += cov

        print '[+]\tExtra coverage   : %d' % self.extra_cov


    # ---------------------------------------------------------------------------------------------
    # Perform some adjustments on the report data. Please note that libFuzzer coverage at each line
    # is the *accumulated* coverage from all loaded modules. If there's a single module we're all
    # good. If not, this introduces some small imprecision to the results. However, we know the
    # total coverage from other modules (stored in self.max_cov) -which is always fairly low-, so
    # we can simply substract it from the current coverage.
    #
    # Another adjustment is to adds 2 more points (0,0) and (max_ts, max_cov) to make plots more
    # beautiful.
    #
    def adjust_report(self, adjust_cov=0):
        # adjust coverage (if needed)
        if adjust_cov:
            self.coverage = [cov - adjust_cov for cov in self.coverage]
            self.max_cov -= adjust_cov

        # find minimum timestamp and subtract it from every element
        self.time = [ts - min(self.time) for ts in self.time]

        # add 2 more element to make beautiful plots
        self.time = [0] + self.time + [TOTAL_FUZZING_SECONDS]
        self.coverage = [0] + self.coverage + [self.coverage[-1]]
        self.execs = [0] + self.execs + [self.execs[-1]]


    # ---------------------------------------------------------------------------------------------
    # Convert absolute coverage (e.g., 4296/12178) into relative (e.g., 35.28%).
    #
    def make_percentage(self, tot_cov=None):
        if not tot_cov:
            tot_cov = self.tot_cov

        for i in range(len(self.coverage)):
            self.coverage[i] /= tot_cov / 100


    # ---------------------------------------------------------------------------------------------
    # Given an arbitrary time t1, find the code coverage at that time. If there's a coverage update
    # at t1, we just return coverage at that time. If not, we first find t0, the nearest time right
    # before t1 with a coverage update. Then we find t2, the nearest time right after t1 with a
    # coverage update. Finally we use linear interpolation to approximate the coverage at t1.
    #
    def calculate_instant_coverage(self, t1):
        # TODO: This is very naive way to do things. Use binary search instead
        
        # Check if there's a coverage update for t1
        if t1 in self.time:
            for i in range(len(self.time)-1, -1, -1):
                if t1 == self.time[i]:
                    return self.coverage[i]         # time found. Just return coverage


        # Otherwise first find t0. Scan list backwards and get the nearest point t1 s.t. t1 > t0
        # Note that there can be multiple coverage updates at t1. so pick the largest
        for i in range(len(self.time)-1, -1, -1):
            if t1 > self.time[i]:
                t0, cov0 = self.time[i], self.coverage[i]
                break

        # Now find t1. Scan list forward.
        for i in range(len(self.time)):
            if t1 < self.time[i]:
                t2, cov2 = self.time[i], self.coverage[i]
                break

        # Do the linear interpolation. Find the slope (a) between these 2 points and use 
        # the equation f(t) = a*t + b to find coverage at t1
        slope = (cov2 - cov0) / (t2 - t0)
        cov1 = cov0 + (t1 - t0) * slope

        return roundup(cov1)



# -------------------------------------------------------------------------------------------------
# This class performs a statistical testing on multiple fuzzing reports. 
#
class StatisticalTest(object):
    # ---------------------------------------------------------------------------------------------
    # Class constructor.
    #
    def __init__(self):
        self.reports = []


    # ---------------------------------------------------------------------------------------------
    # Add a new report to the list.
    #
    def add_report(self, report):
        self.reports.append(report)


    # ---------------------------------------------------------------------------------------------
    # Get the best report (the one with the highest code coverage.
    #
    def get_best_report(self):
        max_cov = -1
        best_report = None

        for report in self.reports:
            if max_cov < report.max_cov:
                max_cov = report.max_cov
                best_report = report

        return best_report


    # ---------------------------------------------------------------------------------------------
    # Get the best report (the one with the highest code coverage.
    #
    def get_worst_report(self):
        max_cov = 99999999
        worst_report = None

        for report in self.reports:
            if max_cov > report.max_cov:
                max_cov = report.max_cov
                worst_report = report

        return worst_report


    # ---------------------------------------------------------------------------------------------
    # Get the max coverage from all reports
    #
    def get_max_covs(self):
        return ','.join([str(report.max_cov) for report in self.reports])


    # ---------------------------------------------------------------------------------------------
    # Calculate the average report from all reports. The problem is that reports have different
    # points (i.e., timestamps with coverage update), so we can't directly find the average
    # coverage. The idea here is to leverage the linear interpolation and find the coverage for
    # the same given time for all reports. Then we simply find the mean coverage.
    #
    def calculate_avg_report(self, tot_cov):
        # Find time points that we want to find the coverage for.
        #
        # Use udpates every second for the first hour, every 10 seconds for the next 3 hours
        # and every minute for the remaining time. We do this to be more precise, since we have
        # more frequent updates during startup.
        self.time = [t for t in range(0, 3600)] + \
                    [t for t in range(3600, 3600*4, 10)] + \
                    [t for t in range(3600*4, TOTAL_FUZZING_SECONDS, 60)] 

        self.coverage = []

        # Find the average coverage for each of the above times
        for t in self.time:
            covs = [report.calculate_instant_coverage(t) for report in self.reports]
            self.coverage.append(avg(covs))


        # Convert coverage into percentages
        for i in range(len(self.coverage)):
            self.coverage[i] /= tot_cov / 100



        # get the max average coverage and its stadard deviation
        self.avg_cov = max(self.coverage)
        self.std_cov = std([cov / tot_cov * 100 for cov in covs])

        # get the average executions per second
        self.avg_execs = avg([report.tot_execs/TOTAL_FUZZING_SECONDS for report in self.reports])

        # get the total bugs found
        self.tot_bugs = sum([report.restarts for report in self.reports])


        # return the mean plot
        return self.time, self.coverage



# -------------------------------------------------------------------------------------------------
# This class analyzes all crashes and finds which ones are unique.
#
class CrashDeduplication(object):
    # ---------------------------------------------------------------------------------------------
    # Class constructor.
    #
    def __init__(self):
        self.crash_hashes  = set()                  # all (unique) hashes from all stack traces
        self.total_crashes = 0                      # total number of crashes found


    # ---------------------------------------------------------------------------------------------
    # This functions generates a hash from a stack trace
    #
    def hash_trace(self, stack_trace):
        for stack_entry in stack_trace:
            # ignore slot ID and address. Module and offset inside the module are sufficient
            _, _, module, offset = stack_entry

            sha1 = hashlib.sha1()
            sha1.update(module + "_" + str(offset) + "|")

        return sha1.hexdigest()


    # ---------------------------------------------------------------------------------------------    
    # This function loads a libFuzzer report and extracts all stack traces from all crashes and
    # timeouts.
    #
    def load_report(self, filename):
        log_stack_trace = False                     # guard to enable/disable stack trace logging
        stack_trace     = []                        # a single stack trace
        
        # filename = '/usr/local/google/home/ispo/FuzzGen/aux/results/libhevc_fuzzgen/libhevc_fuzzgen.p4.log'
        with open(filename, "r") as file:           # read libfuzzer output report
            for line in file:                       # and process it line by line                
                # print line
                # -----------------------------------------------------------------------
                # Part #1: Find the beginning of a crash report. Examples:
                #   ==19462==ERROR: AddressSanitizer: SEGV on unknown address 0x72a5f56000
                #   ==10309==ERROR: AddressSanitizer: heap-buffer-overflow on address
                #       0x76ba8fe7fc at pc 0x005dfb069530 bp 0x007fcd13ff40 sp 0x007fcd13ff38
                #   ==15525== ERROR: libFuzzer: timeout after 1704 seconds
                #   ==4440==AddressSanitizer CHECK failed: /usr/local/...
                # -----------------------------------------------------------------------
                match_st_1 = re.search(r'^\[[0-9]+\] ==[0-9]+==\s*ERROR: ', line)
                match_st_2 = re.search(r'^\[[0-9]+\] ==[0-9]+==\s*AddressSanitizer CHECK failed:',
                                       line)

                if match_st_1 is not None or match_st_2 is not None:
                    self.total_crashes  += 1        # increment bugs found
                    log_stack_trace = True          # start logging
                    stack_trace     = []            # clear trace
                    #print 'start!'


                # -----------------------------------------------------------------------
                # Part #2: Log a stack entry. Examples:
                #   #0 0x64f4795fd3  (/data/nativetest64/fuzzers/libhevc_fuzzer_ispo+0x35fd3)
                # -----------------------------------------------------------------------
                match_strace = re.search(r'^\[[0-9]+\]\s+\#([0-9]+)\s+(0x[0-9a-f]+)\s+'
                                         r'\(([\./a-zA-Z0-9_-]+)\+(0x[0-9a-f]+)\)', line)

                if log_stack_trace and match_strace is not None:
                    slot_id = int(match_strace.group(1))
                    addr    = int(match_strace.group(2), 16)
                    module  = match_strace.group(3)
                    offset  = int(match_strace.group(4), 16)

                    addr = addr & 0xfff             # ASLR is enabled. Focus on the 12 LSBits

                    stack_trace.append((slot_id, addr, module, offset))


                # -----------------------------------------------------------------------
                # Part #3: Find the end of a crash report. Examples:                
                #   ==19462==ABORTING
                #   SUMMARY: libFuzzer: timeout
                # -----------------------------------------------------------------------
                match_end_1 = re.search(r'^\[[0-9]+\] ==[0-9]+==\s*ABORTING', line)
                match_end_2 = re.search(r'^\[[0-9]+\] SUMMARY: libFuzzer: timeout', line)
                
                if match_end_1 is not None or match_end_2 is not None:
                    log_stack_trace = False         # stop logging

                    # calculate the hash of the stack trace and add it to the set
                    stack_hash = self.hash_trace(stack_trace)
                    self.crash_hashes.add(stack_hash)


                # -----------------------------------------------------------------------
                # Part #4: Match out of memory without a stack trace
                #   SUMMARY: libFuzzer: out-of-memory
                # -----------------------------------------------------------------------
                match_oom = re.search(r'^\[[0-9]+\] SUMMARY: libFuzzer: out-of-memory', line)

                if match_oom is not None:
                    # add something unique to the set
                    self.crash_hashes.add('SUMMARY: libFuzzer: out-of-memory')
     

        print '[+] Total crashes so far  : %d' % self.total_crashes
        print '[+] Unique crashes so far : %d' % len(self.crash_hashes)


# -------------------------------------------------------------------------------------------------
# This class provides a convenient interface to plot reports.
#
class PlotReports(object):
    time_interval = 4*3600                          # set a 4-hr interval

    # ---------------------------------------------------------------------------------------------
    # Class constructor.
    #   
    def __init__(self, title, tot_cov, ylabel='Edge Coverage (%)'):
        self.tot_cov = tot_cov

        plt.figure(figsize=(8,5))                   # set dimensions
        plt.rcParams.update({'font.size': 16})
        plt.grid()                                  # add a grid
        #plt.title(title)                           # set title
        plt.xlabel('Time (in hours)')               # add labels
        plt.ylabel(ylabel)
        
        # adjust ticks (cast seconds into hours) and axes.
        plt.axis([-MARGIN_SEC, (len(TIME_TICKS)-1)*3600, 0, self.tot_cov*1.05])
        plt.xticks( [i*3600 for i in range(len(TIME_TICKS))], ['%dhr' % i for i in TIME_TICKS])

        # Add a bold vertical line at 4hr interval
        cov3, time3 = [0, self.tot_cov*1.05], [self.time_interval+1, self.time_interval+1]
        plt.plot(time3, cov3, label='', color='black')


    # ---------------------------------------------------------------------------------------------
    # Add a new report to the plot. The trick here is to "compress time". That is, we pick a 4-hour
    # slot and we divide all times by 4, to compress it into an 1-hour slot. This is the only way
    # to have equal-size ticks in plot while we represent longer intervals.
    #
    def add_plot(self, time, coverage, label, time_compression=True):
        if time_compression:
            # Split time at 4hr
            for i in range(len(time)):
                if time[i] > self.time_interval:
                    delim = i
                    break
            
            time_1 = time[:delim]
            time_2 = time[delim:]

            # Compress time
            time_2 = [t - self.time_interval for t in time_2]
            time_2 = [roundup(t/4) for t in time_2]
            time_2 = [t + self.time_interval for t in time_2]

            plt.plot(time_1 + time_2, coverage, label=label, linewidth=3.0)
    
        else:
            plt.plot(time, coverage, label=label, linewidth=3.0)


    # ---------------------------------------------------------------------------------------------
    # Show all plots.
    #
    def show(self, output):
        print '[+] Showing plot...'        

        #plt.legend(loc='lower right')                   # add legends       

        plt.legend(loc='upper center', bbox_to_anchor=(0.5, -0.05),
                    fancybox=True, shadow=True, ncol=5)

        # save figure (set bbox_inches to tight to auto crop the extra white from the plot )
        plt.savefig(output + '.pdf', format='pdf', bbox_inches='tight')
        


        print "[+] Figure saved as '%s.pdf' " % output        

        plt.show()                                      # and display it



# -------------------------------------------------------------------------------------------------
# Parse the command line arguments.
#
def parse_args():
    # create the parser object and the groups
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument(
        "--ispo_dir",
        help     = "Directory with all fuzzing reports from Ispo's fuzzers",
        action   = 'store',
        dest     = 'ispo_dir',
        required = True
    )

    parser.add_argument(
        "--fuzzgen_dir",
        help     = "Directory with all fuzzing reports from FuzzGen fuzzers",
        action   = 'store',
        dest     = 'fuzzgen_dir',
        required = True
    )

    parser.add_argument(
        "--ispo-total-cov",
        help     = "Total coverage of the library for ispo fuzzer",
        action   = 'store',
        dest     = 'ispo_total_cov',
    )

    parser.add_argument(
        "--fuzzgen-total-cov",
        help     = "Total coverage of the library for FuzzGen fuzzer",
        action   = 'store',
        dest     = 'fuzzgen_total_cov',
    )

    parser.add_argument(
        "--fuzzer_name",
        help     = "Fuzzer name (e.g. libhevc)",
        action   = 'store',
        dest     = 'fuzzer_name',
        required = True
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)

    return parser.parse_args()                      # do the parsing (+ error handling)



# -------------------------------------------------------------------------------------------------
# This is the main function. 
#
if __name__ == '__main__':
    # -------------------------------------------------------------------------
    # Plot consumer tail off
    # -------------------------------------------------------------------------
 
    print "[+] Adding curves to the plot ..."
    plt.figure(figsize=(8,5))                   # set dimensions
    plt.rcParams.update({'font.size': 16})
    plt.grid()                                  # add a grid
    plt.xlabel('# of Consumers')               # add labels
    plt.ylabel('# of API Calls')
        
    plt.axis([0, 15, 0, 66])
    plt.xticks([i for i in range(0,16)])


    plt.plot([i for i in range(0, 16)], 
                  [0, 6,  6,  10, 12, 25, 31, 33, 44, 47, 50, 51, 53, 56, 56, 56],
                  label='API calls used in the Fuzzer', linewidth=3.0)
    
    plt.plot([i for i in range(0, 16)], 
                  [0, 34, 34, 34, 34, 51, 51, 65, 65, 65, 65, 65, 65, 65, 65, 65],
                  label='Total API calls identified', linewidth=3.0)


    plt.legend(loc='lower right')                   # add legends       
    plt.show() 

    exit()


    args = parse_args()                             # parse arguments
    now = datetime.datetime.now()
    ispo_tot_cov = 999999
    fuzzgen_tot_cov = 999999

    ispo_maxcov = []
    fuzzgen_maxcov = []


    print "[+] Starting 'plot_coverage' tool (FuzzGen auxiliary) at %s" % \
          now.strftime("%d/%m/%Y %H:%M")


    # -------------------------------------------------------------------------
    # Process ispo fuzz reports
    # -------------------------------------------------------------------------
    print "[+] ----------------------------------------------------------------"
    print "[+] Processing ispo's fuzz reports ..."    
    ispo_statest = StatisticalTest()
    ispo_dedup   = CrashDeduplication()
    
    for logfile in os.listdir(args.ispo_dir):
        if logfile.endswith(".log"):                # focus on *.log files only
            full_path = os.path.join(args.ispo_dir, logfile)

            print "[+] Processing report '%s' ..." % logfile

            fuzz_report = FuzzReport(logfile, args.fuzzer_name)
            fuzz_report.load_report(full_path)

            if fuzz_report.modules == 1:
                fuzz_report.adjust_report(0)                
            else:
                print '[!] Adjusting coverage report by %d' % fuzz_report.extra_cov
                fuzz_report.adjust_report(fuzz_report.extra_cov)

            ispo_tot_cov = min(ispo_tot_cov, fuzz_report.tot_cov)            
            ispo_statest.add_report(fuzz_report)

            print "[+] Analyzing crashes ..."
            ispo_dedup.load_report(full_path)

    print '[+] Ispo total crashes  : %d' % ispo_dedup.total_crashes
    print '[+] Ispo unique crashes : %d' % len(ispo_dedup.crash_hashes)


    # -------------------------------------------------------------------------
    # Process FuzzGen fuzz reports
    # -------------------------------------------------------------------------
    print "[+] ----------------------------------------------------------------"
    print "[+] Processing FuzzGen fuzz reports ..."
    fuzzgen_statest = StatisticalTest()
    fuzzgen_dedup   = CrashDeduplication()

    for logfile in os.listdir(args.fuzzgen_dir):
        if logfile.endswith(".log"):                # focus on *.log files only
            full_path = os.path.join(args.fuzzgen_dir, logfile)

            print "[+] Processing report '%s' ..." % logfile

            fuzz_report = FuzzReport(logfile, args.fuzzer_name)
            fuzz_report.load_report(full_path)

            if fuzz_report.modules == 1:
                fuzz_report.adjust_report(0)  
            else:
                print '[!] Adjusting coverage report by %d' % fuzz_report.extra_cov
                fuzz_report.adjust_report(fuzz_report.extra_cov)

            fuzzgen_tot_cov = min(fuzzgen_tot_cov, fuzz_report.tot_cov)
            fuzzgen_statest.add_report(fuzz_report)

            print "[+] Analyzing crashes ..."
            fuzzgen_dedup.load_report(full_path)

    print '[+] FuzzGen total crashes  : %d' % fuzzgen_dedup.total_crashes
    print '[+] FuzzGen unique crashes : %d' % len(fuzzgen_dedup.crash_hashes)


    # -------------------------------------------------------------------------
    # Do the statistical testing
    # -------------------------------------------------------------------------

    # Get total coverage if provided
    if args.ispo_total_cov:
        ispo_tot_cov = int(args.ispo_total_cov)

    if args.fuzzgen_total_cov:
        fuzzgen_tot_cov = int(args.fuzzgen_total_cov)

    print "[+] Ispo total coverage   : %d" % ispo_tot_cov
    print "[+] FuzzGen total coverage: %d" % fuzzgen_tot_cov

    if ispo_tot_cov == 999999 or fuzzgen_tot_cov == 999999:
        print "[!] Error. Total coverage is undefined."


    print "[+] ----------------------------------------------------------------"
    print "[+] Performing the statistical testing ..."

    time_avg_ispo, cov_avg_ispo = ispo_statest.calculate_avg_report(ispo_tot_cov)
    best_ispo = ispo_statest.get_best_report()
    best_ispo.make_percentage(ispo_tot_cov)
    
    time_avg_fuzzgen, cov_avg_fuzzgen = fuzzgen_statest.calculate_avg_report(fuzzgen_tot_cov)
    best_fuzzgen = fuzzgen_statest.get_best_report()
    best_fuzzgen.make_percentage(fuzzgen_tot_cov)
    
    worst_ispo = ispo_statest.get_worst_report()
    worst_fuzzgen = fuzzgen_statest.get_worst_report()

    print "[+] Ispo Fuzzer statistics:"
    print "[+]\tBest Coverage    : %.2f%%" % (best_ispo.max_cov / ispo_tot_cov * 100)
    print "[+]\tAverage Coverage : %.2f%%" % ispo_statest.avg_cov
    print "[+]\tWorst Coverage   : %.2f%%" % (worst_ispo.max_cov / ispo_tot_cov * 100)
    print "[+]\tCoverage Std Dev : %.2f"   % ispo_statest.std_cov
    print "[+]\tAverage exec/s   : %d"     % ispo_statest.avg_execs
    print "[+]\tTotal Bugs       : %d"     % ispo_statest.tot_bugs
    print "[+]"

    print "[+] FuzzGen Fuzzer statistics:"
    print "[+]\tBest Coverage    : %.2f%%" % (best_fuzzgen.max_cov / fuzzgen_tot_cov * 100)    
    print "[+]\tAverage Coverage : %.2f%%" % fuzzgen_statest.avg_cov
    print "[+]\tWorst Coverage   : %.2f%%" % (worst_fuzzgen.max_cov / fuzzgen_tot_cov * 100)    
    print "[+]\tCoverage Std Dev : %.2f"   % fuzzgen_statest.std_cov
    print "[+]\tAverage exec/s   : %d"     % fuzzgen_statest.avg_execs
    print "[+]\tTotal Bugs       : %d"     % fuzzgen_statest.tot_bugs
    print "[+]"


    print "[+] Ispo Max Coverage   :", ispo_statest.get_max_covs()
    print "[+] FuzzGen Max Coverage:", fuzzgen_statest.get_max_covs()


    # Caclulate total % coverage (add a margin of 10%)
    tot_cov = max(best_ispo.max_cov    / ispo_tot_cov    * 100, 
                  best_fuzzgen.max_cov / fuzzgen_tot_cov * 100) + 8

    # -------------------------------------------------------------------------
    # Plot all curves
    # -------------------------------------------------------------------------
    print "[+] Adding curves to the plot ..."
    plot = PlotReports(args.fuzzer_name, tot_cov)

    plot.add_plot(time_avg_ispo, cov_avg_ispo, 'Manual Fuzzer Average')
    plot.add_plot(best_ispo.time, best_ispo.coverage, 'Manual Fuzzer Best Single Run')

    plot.add_plot(time_avg_fuzzgen,  cov_avg_fuzzgen, 'FuzzGen Fuzzer Average')
    plot.add_plot(best_fuzzgen.time, best_fuzzgen.coverage, 'FuzzGen Fuzzer Best Single Run')

    # No total coverage (everything is %) 
    #
    # plot the total coverage (it's a straight line, so 2 points are enough)
    # plot.add_plot([-MARGIN_SEC, TOTAL_FUZZING_SECONDS], [int(tot_cov)]*2, 'Total Coverage',
    #               time_compression=False)

   # plot.show(args.fuzzer_name) 


    # plot executions per second
    print "[+] Adding exec/s curves to the plot ..."

    max_execs = max(max(best_ispo.execs), max(best_fuzzgen.execs))

    #plot2 = PlotReports(args.fuzzer_name, max_execs, 'Executions per second')
    #plot2.add_plot(best_ispo.time, best_ispo.execs, 'Manual Fuzzer')
    #plot2.add_plot(best_fuzzgen.time, best_fuzzgen.execs, 'FuzzGen Fuzzer')
    #plot2.show(args.fuzzer_name + '_execs') 


    print "[+] Program finished!"
    print "[+] Bye bye :)"


# -------------------------------------------------------------------------------------------------
'''
time ./plot_libfuzzer_coverage.py --fuzzgen_dir results/libhevc_fuzzgen  --ispo_dir results/libhevc_ispo  --fuzzer_name libhevc
time ./plot_libfuzzer_coverage.py --fuzzgen_dir results/libavc_fuzzgen   --ispo_dir results/libavc_ispo   --fuzzer_name libavc --fuzzgen-total-cov 7179
time ./plot_libfuzzer_coverage.py --fuzzgen_dir results/libmpeg2_fuzzgen --ispo_dir results/libmpeg2_ispo --fuzzer_name libmpeg2
time ./plot_libfuzzer_coverage.py --fuzzgen_dir results/libopus_fuzzgen  --ispo_dir results/libopus_ispo  --fuzzer_name libopus
time ./plot_libfuzzer_coverage.py --fuzzgen_dir results/libgsm_fuzzgen   --ispo_dir results/libgsm_ispo   --fuzzer_name libgsm
time ./plot_libfuzzer_coverage.py --fuzzgen_dir results/libvpx_fuzzgen   --ispo_dir results/libvpx_ispo   --fuzzer_name libvpx
time ./plot_libfuzzer_coverage.py --fuzzgen_dir results/libaom_fuzzgen   --ispo_dir results/libaom_ispo   --fuzzer_name libaom

ispo@ispo1:~/FuzzGen/aux$ time ./plot_libfuzzer_coverage.py --fuzzgen_dir results/libavc_fuzzgen   --ispo_dir results/libavc_ispo   --fuzzer_name libavc --fuzzgen-total-cov 7179
[+] Starting 'plot_coverage' tool (FuzzGen auxiliary) at 19/08/2019 17:44
[+] ----------------------------------------------------------------
[+] Processing ispo's fuzz reports ...
[+] Processing report 'libavc_ispo.p6.log' ...
[+] Total coverage   : 7121
[+] Maximum coverage : 3754 (52.72%)
[+] Total executions : 855982
[+] Average exec/s   : 10
[+] Total restarts   : 87
[+] Corpus count     : 7631 files
[+] Sanitize Coverage:
[+]          libavc_fuzzer_ispo: 3754
[+] Extra coverage   : 0
[+] Analyzing crashes ...
[+] Total crashes so far  : 86
[+] Unique crashes so far : 1
[+] Processing report 'libavc_ispo.p8.log' ...
[+] Total coverage   : 7121
[+] Maximum coverage : 3861 (54.22%)
[+] Total executions : 789117
[+] Average exec/s   : 10
[+] Total restarts   : 47
[+] Corpus count     : 8353 files
[+] Sanitize Coverage:
[+]          libavc_fuzzer_ispo: 3861
[+] Extra coverage   : 0
[+] Analyzing crashes ...
[+] Total crashes so far  : 132
[+] Unique crashes so far : 1
[+] Processing report 'libavc_ispo.p3.log' ...
[+] Total coverage   : 7121
[+] Maximum coverage : 3910 (54.91%)
[+] Total executions : 913766
[+] Average exec/s   : 11
[+] Total restarts   : 45
[+] Corpus count     : 9798 files
[+] Sanitize Coverage:
[+]          libavc_fuzzer_ispo: 3910
[+] Extra coverage   : 0
[+] Analyzing crashes ...
[+] Total crashes so far  : 177
[+] Unique crashes so far : 1
[+] Processing report 'libavc_ispo.p5.log' ...
[+] Total coverage   : 7121
[+] Maximum coverage : 3633 (51.02%)
[+] Total executions : 433577
[+] Average exec/s   : 6
[+] Total restarts   : 50
[+] Corpus count     : 6135 files
[+] Sanitize Coverage:
[+]          libavc_fuzzer_ispo: 3633
[+] Extra coverage   : 0
[+] Analyzing crashes ...
[+] Total crashes so far  : 226
[+] Unique crashes so far : 1
[+] Processing report 'libavc_ispo_2.p6.log' ...
[+] Total coverage   : 7121
[+] Maximum coverage : 3184 (44.71%)
[+] Total executions : 116803
[+] Average exec/s   : 2
[+] Total restarts   : 10
[+] Corpus count     : 2572 files
[+] Sanitize Coverage:
[+]          libavc_fuzzer_ispo: 3175
[+] Extra coverage   : 0
[+] Analyzing crashes ...
[+] Total crashes so far  : 236
[+] Unique crashes so far : 1
[+] Processing report 'libavc_ispo.p7.log' ...
[+] Total coverage   : 7121
[+] Maximum coverage : 3857 (54.16%)
[+] Total executions : 664654
[+] Average exec/s   : 8
[+] Total restarts   : 47
[+] Corpus count     : 6447 files
[+] Sanitize Coverage:
[+]          libavc_fuzzer_ispo: 3857
[+] Extra coverage   : 0
[+] Analyzing crashes ...
[+] Total crashes so far  : 283
[+] Unique crashes so far : 1
[+] Ispo total crashes  : 283
[+] Ispo unique crashes : 1
[+] ----------------------------------------------------------------
[+] Processing FuzzGen fuzz reports ...
[+] Processing report 'libavc_fuzzgen.p3.log' ...
[+] Total coverage   : 7179
[+] Maximum coverage : 4641 (64.65%)
[+] Total executions : 5664783
[+] Average exec/s   : 66
[+] Total restarts   : 1
[+] Corpus count     : 4201 files
[+] Sanitize Coverage:
[+]     libavc_fuzzer_main-main: 4641
[+] Extra coverage   : 0
[+] Analyzing crashes ...
[+] Total crashes so far  : 0
[+] Unique crashes so far : 0
[+] Processing report 'libavc_fuzzgen.lab.log' ...
[+] Total coverage   : 28880
[+] Maximum coverage : 5423 (18.78%)
[+] Total executions : 20259238
[+] Average exec/s   : 235
[+] Total restarts   : 0
[+] Corpus count     : 6 files
[!] Fuzzer has 6 modules. Coverage may be inaccurate
[+] Sanitize Coverage:
[+]     libavc_fuzzer_main-main: 4669
[+]                   libc++.so: 320
[+]           libnetd_client.so: 14
[+]                 libutils.so: 19
[+] Extra coverage   : 353
[!] Adjusting coverage report by 353
[+] Analyzing crashes ...
[+] Total crashes so far  : 0
[+] Unique crashes so far : 0
[+] Processing report 'libavc_fuzzgen_2.lab.log' ...
[+] Total coverage   : 28880
[+] Maximum coverage : 5022 (17.39%)
[+] Total executions : 20259238
[+] Average exec/s   : 235
[+] Total restarts   : 0
[+] Corpus count     : 6 files
[!] Fuzzer has 6 modules. Coverage may be inaccurate
[+] Sanitize Coverage:
[+]     libavc_fuzzer_main-main: 4669
[+]                   libc++.so: 320
[+]           libnetd_client.so: 14
[+]                 libutils.so: 19
[+] Extra coverage   : 353
[!] Adjusting coverage report by 353
[+] Analyzing crashes ...
[+] Total crashes so far  : 0
[+] Unique crashes so far : 0
[+] Processing report 'libavc_fuzzgen.p8.log' ...
[+] Total coverage   : 7179
[+] Maximum coverage : 4659 (64.90%)
[+] Total executions : 12454469
[+] Average exec/s   : 145
[+] Total restarts   : 1
[+] Corpus count     : 5058 files
[+] Sanitize Coverage:
[+]     libavc_fuzzer_main-main: 4659
[+] Extra coverage   : 0
[+] Analyzing crashes ...
[+] Total crashes so far  : 0
[+] Unique crashes so far : 0
[+] Processing report 'libavc_fuzzgen.p4.log' ...
[+] Total coverage   : 7179
[+] Maximum coverage : 4643 (64.67%)
[+] Total executions : 6295209
[+] Average exec/s   : 73
[+] Total restarts   : 1
[+] Corpus count     : 4286 files
[+] Sanitize Coverage:
[+]     libavc_fuzzer_main-main: 4643
[+] Extra coverage   : 0
[+] Analyzing crashes ...
[+] Total crashes so far  : 0
[+] Unique crashes so far : 0
[+] FuzzGen total crashes  : 0
[+] FuzzGen unique crashes : 0
[+] Ispo total coverage   : 7121
[+] FuzzGen total coverage: 7179
[+] ----------------------------------------------------------------
[+] Performing the statistical testing ...
[+] Ispo Fuzzer statistics:
[+] Best Coverage    : 54.91%
[+] Average Coverage : 0.71%
[+] Coverage Std Dev : 4.28
[+] Average exec/s   : 8
[+] Total Bugs       : 286
[+]
[+] FuzzGen Fuzzer statistics:
[+] Best Coverage    : 70.62%
[+] Average Coverage : 0.92%
[+] Coverage Std Dev : 2.33
[+] Average exec/s   : 151
[+] Total Bugs       : 3
[+]
[+] Ispo Max Coverage   : 3754,3861,3910,3633,3184,3857
[+] FuzzGen Max Coverage: 4641,5070,4669,4659,4643
[+] Adding curves to the plot ...
[+] Showing plot...
[+] Figure saved as 'libavc.pdf' 
[+] Adding exec/s curves to the plot ...
[+] Program finished!
[+] Bye bye :)

real    0m20.146s
user    0m15.055s
sys 0m3.787s
'''
# -------------------------------------------------------------------------------------------------
