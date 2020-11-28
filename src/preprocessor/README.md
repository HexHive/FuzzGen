
### Preprocessor Build Instructions

Copy this directory under `$LLVM_SRC/tools/clang/tools`.

Add the following line in `$LLVM_SRC/tools/clang/tools/CMakeLists.txt`.
```
add_clang_subdirectory(fuzzgen)
```

And build LLVM.

To run the FuzzGen preprocessor type:
```
    $BUILD_LLVM_DIR/bin/fuzzgen-preprocessor     \
        -outfile=libavc.meta                     \
        -library-root=/home/ispo/FuzzGen/allsrc  \ 
        $(find ~/FuzzGen/allsrc/external/libavc) \
```
