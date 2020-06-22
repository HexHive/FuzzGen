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
# ~~~ THIS MAKEFILE HAS BEEN GENERATED AUTOMATICALLY BY *FUZZGEN* AT: 27-02-2019 01:28:31 EET ~~~
#
#
LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_CERTIFICATE      := platform
LOCAL_C_INCLUDES       += bionic/libc/include external/libmpeg2/common external/libmpeg2/decoder
LOCAL_SRC_FILES        := main-mainfuzzer.cpp
LOCAL_CFLAGS           += -Wno-multichar -g -Wno-error
LOCAL_MODULE_TAGS      := optional
LOCAL_CLANG            := true
LOCAL_MODULE           := libmpeg2_fuzzer_main-main
LOCAL_SHARED_LIBRARIES := libutils 
LOCAL_STATIC_LIBRARIES += liblog libmpeg2dec

include $(BUILD_FUZZ_TEST)
################################################################################
