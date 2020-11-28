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
project(FuzzGen)

set(LLVM_INCLUDE_DIRS /home/ispo/GIANT/build-llvm)


find_package(LLVM REQUIRED CONFIG)
find_package(Boost REQUIRED)

if(NOT Boost_FOUND)
    message(FATAL_ERROR "BOOST library not found")
endif()

message(STATUS "Generating makefiles for FuzzGen...")
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")


message(STATUS "DEBUG: ${LLVM_INCLUDE_DIRS}")
message(STATUS "DEBUG: ${LLVM_DEFINITIONS}")


include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

# add flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Werror -Wno-error=unused-variable")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")


# build fuzzgen
add_executable(fuzzgen src/main.cpp src/common.cpp src/analyze.cpp
                       src/infer_api.cpp 
                       src/root.cpp 
                       src/dig.cpp src/magic.cpp src/internal.cpp                        
                       src/external.cpp src/layout.cpp src/coalesce.cpp
                       src/dependence.cpp src/backward.cpp src/failure.cpp
                       src/interwork.cpp src/compose.cpp)

# find libraries that you'll use for LLVM components
set(LLVM_LINK_COMPONENTS Analysis)

# and link them
llvm_map_components_to_libnames(llvm_libs support core irreader Analysis)
# llvm_map_components_to_libnames(LLVM_LIBRARIES core support irreader ScalarOpts linker
#       Analysis object transformutils)

# Link against LLVM libraries
target_link_libraries(fuzzgen ${llvm_libs}) # clang)



message(STATUS "Libs: ${llvm_libs}")
