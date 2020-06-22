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
# ~~~ THIS MAKEFILE HAS BEEN GENERATED AUTOMATICALLY BY *FUZZGEN* AT: 30-09-2019 00:35:53 PDT ~~~
#
#
LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_CERTIFICATE      := platform
LOCAL_C_INCLUDES       += bionic/libc/include external/libopus/include external/libopus/src
LOCAL_SRC_FILES        := opus_decode_fuzzer-LLVMFuzzerTestOneInput+test_opus_api-main+opus_demo-main+opus_encode_regressions-regression_test+repacketizer_demo-main+test_opus_encode-main+test_opus_padding-main+trivial_example-mainfuzzer.cpp
LOCAL_CFLAGS           += -Wno-multichar -g -Wno-error
LOCAL_MODULE_TAGS      := optional
LOCAL_CLANG            := true
LOCAL_MODULE           := libopus_fuzzer_opus_decode_fuzzer-LLVMFuzzerTestOneInput+test_opus_api-main+opus_demo-main+opus_encode_regressions-regression_test+repacketizer_demo-main+test_opus_encode-main+test_opus_padding-main+trivial_example-main
LOCAL_SHARED_LIBRARIES := libutils 
LOCAL_STATIC_LIBRARIES += liblog libopus

include $(BUILD_FUZZ_TEST)
################################################################################
