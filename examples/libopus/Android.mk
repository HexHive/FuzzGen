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
# ~~~ THIS MAKEFILE HAS BEEN GENERATED AUTOMATICALLY BY *FUZZGEN* AT: 25-02-2019 13:19:08 EET ~~~
#
#
LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

# decoder
include  \
    $(LOCAL_PATH)/opus_decode_fuzzer-LLVMFuzzerTestOneInput+test_opus_padding-main+trivial_example-main/Android.mk
