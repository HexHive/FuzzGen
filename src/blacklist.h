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
 * blacklist.h
 *
 * This file contains a blacklist with all common API functions that we encountered during
 * evaluation and should not be included in the fuzzer.
 *
 * NOTE: This list is not complete. Please check it (and update it) for each new library.
 */
// ------------------------------------------------------------------------------------------------
#ifndef LIBRARY_BLACKLIST_H
#define LIBRARY_BLACKLIST_H

#include "common.h"



// ------------------------------------------------------------------------------------------------
// Common API function names or "parts", that should be excluded from API set. Some functions
// cause problems to libFuzzer while they don't trigger any bugs. For instance API functions that
// deal with threads can cause serious problems in the fuzzer during runtime. Or, fuzzing the
// sleep() function, makes libFuzzer hangs as the argument will probably have a very large value.
// Also functions that terminate/halt the library and/or the whole program should be avoided as
// well.
//
const set<string> blacklist = {
    /* these function parts slow down or abort execution */
    "sleep",     "Sleep",
    "exit",      "Exit",
    "terminate", "Terminate",
    "abort",     "Abort",
    "suspend",   "Suspend",
    "die",

    /* avoid thread management functions used by libhevc, libavc and libmpeg2 */
    "ithread_",

    /* these functions don't do anything useful, but libopus consumers use them all the time */
    "opus_get_version_string",
    "opus_strerror",
 
    /* PNG functions */
    "png_init_io",
    "png_image_begin_read_from_file",
    "png_image_finish_read",
    "png_image_write_to_file",
    "png_image_free",


    /* libaom IO */
    "aom_video_reader_open",
    "aom_video_reader_get_info",
    "get_aom_decoder_by_fourcc",
    "aom_video_reader_read_frame",    
    "aom_video_reader_get_frame",
    "aom_video_reader_close",
    "aom_video_writer_open",
    "aom_video_writer_close",

    "aom_img_write",
    "aom_img_read",


    /* OPT: Feel free to extend this list */

    /* add something dummy so you can always have a comma after the last string */
    "$$_JUST_A_VERY_LONG_AND_RANDOM_STRING_THAT_YOU_WILL_NEVER_HIT_$$"
};

// ------------------------------------------------------------------------------------------------
#endif
