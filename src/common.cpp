// ------------------------------------------------------------------------------------------------
/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *
 *      ___        ___           ___           ___           ___           ___           ___
 *     /\__\      /\  \         /\__\         /\__\         /\__\         /\__\         /\  \
 *    /:/ _/_     \:\  \       /::|  |       /::|  |       /:/ _/_       /:/ _/_        \:\  \
 *   /:/ /\__\     \:\  \     /:/:|  |      /:/:|  |      /:/ /\  \     /:/ /\__\        \:\  \
 *  /:/ /:/  / ___  \:\  \   /:/|:|  |__   /:/|:|  |__   /:/ /::\  \   /:/ /:/ _/_   _____\:\  \
 * /:/_/:/  / /\  \  \:\__\ /:/ |:| /\__\ /:/ |:| /\__\ /:/__\/\:\__\ /:/_/:/ /\__\ /::::::::\__\
 * \:\/:/  /  \:\  \ /:/  / \/__|:|/:/  / \/__|:|/:/  / \:\  \ /:/  / \:\/:/ /:/  / \:\~~\~~\/__/
 *  \::/__/    \:\  /:/  /      |:/:/  /      |:/:/  /   \:\  /:/  /   \::/_/:/  /   \:\  \
 *   \:\  \     \:\/:/  /       |::/  /       |::/  /     \:\/:/  /     \:\/:/  /     \:\  \
 *    \:\__\     \::/  /        |:/  /        |:/  /       \::/  /       \::/  /       \:\__\
 *     \/__/      \/__/         |/__/         |/__/         \/__/         \/__/         \/__/
 *
 * FuzzGen - Automatic Fuzzer Generation
 *
 *
 *
 * common.cpp
 *
 * This file contains the actual functions as declared in common.h.
 *
 */
// ------------------------------------------------------------------------------------------------
#include "common.h"



// ------------------------------------------------------------------------------------------------
// Get current date and time.
//
std::string now(void) {
    time_t    t   = time(0);
    struct tm now = *localtime(&t);
    char      time[64];


    strftime(time, 64, "%d-%m-%Y %X %Z", &now);

    return string(time);
}



// ------------------------------------------------------------------------------------------------
// Ask permission from user to continue execution.
//
bool continueExecution(std::string msg, Context *ctx) {
    char ans;


    if (ctx->yes) {                                 // if yes option is set, just continue
        return true;
    }

    if (msg != "") {
        remark(v0) << msg << "\n";                  // display a message if exists
    }

    remark(v0) << "Continue? [y/n] ";

    std::cin >> ans;


    return ans != 'n';
}



// ------------------------------------------------------------------------------------------------
// Check whether a string is a suffix of another
//
bool isSuffix(std::string suffix, std::string str) {


    int st_pos = (int)str.length() - (int)suffix.length();

    if (st_pos < 0) {
        return false;
    }


    return str.substr(st_pos) == suffix;
}



// ------------------------------------------------------------------------------------------------
// Report an issue.
//
void Context::reportIssue(std::string msg) {
    issues.push(msg);                               // simply push it to the queue (FIFO)
}



// ------------------------------------------------------------------------------------------------
// Pack all issues into a string (without duplicates) and return it.
//
std::string Context::dumpIssues(void) {
    std::map<std::string, bool> rec;        	   // record already logged issues
    std::string                 report("\n");       // final report


    /* if there are no issues, don't do anything */
    if (issues.size() < 1) {
        return "-";
    }

    /* iterate over issues */
    for (; !issues.empty(); issues.pop()) {
        /* if issue is already recorded, skip it */
        if (rec.find(issues.front()) != rec.end()) {
            continue;
        }

        /* record current issue */
        rec[ issues.front() ] = true;

        /* log issue */
        report += " *   > " + issues.front() + "\n";
    }

    return report + " *";                           // return all issues
}

// ------------------------------------------------------------------------------------------------
