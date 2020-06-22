#
# Copyright (C) 2017 The Android Open Source Project
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
# ~~~ THIS MAKEFILE HAS BEEN GENERATED AUTOMATICALLY BY *FUZZGEN* AT: 14-12-2018 00:44:01 CET ~~~
#
#
LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

# decoder
include  \
    $(LOCAL_PATH)/cod2lin-main/Android.mk \
    $(LOCAL_PATH)/cod2txt-main/Android.mk \
    $(LOCAL_PATH)/gsm2cod-main/Android.mk \
    $(LOCAL_PATH)/lin2cod-main/Android.mk \
    $(LOCAL_PATH)/lin2txt-main/Android.mk
