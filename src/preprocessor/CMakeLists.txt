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
cmake_minimum_required(VERSION 3.4.3)
project(FuzzGenPreprocessor)


set(LLVM_LINK_COMPONENTS ${LLVM_TARGETS_TO_BUILD} asmparser support mc)

add_clang_executable(fuzzgen-preprocessor preprocessor.cpp)

target_link_libraries(fuzzgen-preprocessor
    PRIVATE
    clangAST
    clangBasic
    clangCrossTU
    clangFrontend
    clangIndex
    clangTooling
)

install(TARGETS fuzzgen-preprocessor RUNTIME DESTINATION bin)
