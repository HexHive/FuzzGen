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
 * preprocessor.h
 *
 * Header file for preprocessor.cpp
 *
 */
// ------------------------------------------------------------------------------------------------
#ifndef LIBRARY_PREPROCESSOR_H
#define LIBRARY_PREPROCESSOR_H

#include "clang/Frontend/CompilerInstance.h"        // clang includes
#include "clang/Frontend/FrontendActions.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/GlobalDecl.h"
#include "clang/AST/Mangle.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/AST/AST.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/RecursiveASTVisitor.h"

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/Signals.h"

#include <iostream>                                 // c++ includes
#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include <set>
#include <map>

#include <stdio.h>                                  // c includes (for file locks)
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <linux/limits.h>



/* MACROs */
#define CURRENT_VERSION         "v3.1"              // fuzzgen preprocessor current version
#define DEFAULT_META_FILENAME   "lib.meta"          // default output file for metadata



using namespace clang;
using namespace clang::tooling;
using namespace llvm;
using namespace std;


/* banner string to put on top of metadata file */
const string banner = R"(#
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
# FuzzGen - Automatic Fuzzer Generation
#)";



// ------------------------------------------------------------------------------------------------
// Recursively visit nodes from AST and analyze the "important" ones.
//
class Visitor : public RecursiveASTVisitor<Visitor> {
public:
    /* class constructor */
    Visitor(SourceManager &, set<string> &, set<string> &, map<string, set<string>> &,
            map<uint64_t, vector<string>> &, map<uint64_t, string> &, map<string, set<string>> &,
            map<string, set<string>> &, map<string, vector<string>> &, string);

    /* callback when a function declaration is encountered */
    bool VisitFunctionDecl(FunctionDecl *);

    /* callback when a variable declaration is encountered */
    bool VisitVarDecl(VarDecl *);

    /* callback when a struct declaration is encountered */
    bool VisitRecordDecl(RecordDecl *);

    /* callback when a struct field is encountered */
    bool VisitFieldDecl(FieldDecl *);

    /* callback when a typedef declaration is encountered */
    bool VisitTypedefDecl(TypedefDecl *);

    /* callback when a enum declaration is encountered */
    bool VisitEnumDecl(EnumDecl *);

    /* callback when a statement is encounterned */
    bool VisitStmt(Stmt *);


private:
    SourceManager            &srcMgr;               // source manager object
    set<string>              &funHdrs, &gloHdrs;    // store headers for each function
    map<string, set<string>> &arrRefs;              // store array arguments for each function
    map<uint64_t, vector<string>> &strFlds;         // store struct fields
    map<uint64_t, string>         &strAddrs;        // store struct object addresses
    map<string, set<string>>      &signParams;      // store signed parameters
    map<string, set<string>>      &constParams;     // store constant parameters
    map<string, vector<string>>   &paramNames;      // store parameter names

    string           curFun, curMod;                // current function and module names
    map<string, int> param;                         // current function parameters
    string           libroot;                       // library root directory


    /* push a global declaration to the globals table */
    bool pushGlobal(NamedDecl *, string="");

    /* check whether a qualified type is signed or not */
    bool isUnsignedTy(QualType, string &);
};



// ------------------------------------------------------------------------------------------------
// Intermediate class that is actually a wrapper for the AST visitor.
//
class ASTProcessor : public ASTConsumer {
public:
    /* class constructor */
    ASTProcessor(set<string> &, set<string> &, map<string, set<string>> &,
                 map<uint64_t, vector<string>> &, map<uint64_t, string> &,
                 map<string, set<string>> &, map<string, set<string>> &,
                 map<string, vector<string>> &, string);

    /* after the entire translation unit's AST has been parsed, this callback is invoked */
    void HandleTranslationUnit(ASTContext& context) override;


private:
    set<string>                   &funHdrs, &gloHdrs;
    map<string, set<string>>      &arrRefs;
    map<uint64_t, vector<string>> &strFlds;
    map<uint64_t, string>         &strAddrs;
    map<string, set<string>>      &signParams;
    map<string, set<string>>      &constParams;
    map<string, vector<string>>   &paramNames;

    string libroot;                                 // library root directory
};



// ------------------------------------------------------------------------------------------------
// Find all dependencies between #include directives.
//
class IncludesProcessor : public PPCallbacks {
public:
    /* class constructor */
    IncludesProcessor(CompilerInstance &,  map<string, vector<string>> &, string);


protected:
    /* callback that is invoked when an #include (or #import) is encountered */
    virtual void InclusionDirective(SourceLocation, const Token &, StringRef, bool, CharSourceRange,
                                    const FileEntry *, StringRef, StringRef, const clang::Module *, 
                                    SrcMgr::CharacteristicKind);


private:
    CompilerInstance            &compInst;          // compiler instance from ASTFrontendAction
    map<string, vector<string>> &incDeps;           // include dependencies reference
    string                      libroot;            // library root directory
};



// ------------------------------------------------------------------------------------------------
// Catch diagnostic messages generated during compilation. As each file is processed individually,
// there will be #include dependencies, so many errors will be created. Here we are only interested
// in syntax analysis, so we don't care if compilation fails at later steps. To prevent these
// errors from flooding the terminal, we add a hook to catch n' kill them.
//
class FuzzGenDiagnosticConsumer : public clang::DiagnosticConsumer {
public:
    /* hook to handle a diagnostic message */
    void HandleDiagnostic(DiagnosticsEngine::Level, const Diagnostic &) override {
        /* Don't do anything */
    }
};



// ------------------------------------------------------------------------------------------------
// Main class for the clang plugin.
//
class FuzzGenPreprocessor : public ASTFrontendAction {
public:
    /* class constructor */
    FuzzGenPreprocessor();


protected:
    /* create the AST consumer object */
    unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &, StringRef) override;

    /* callback before input processing */
    bool BeginSourceFileAction (CompilerInstance &) override;

    /* callback after input processing */
    void EndSourceFileAction() override;


private:
    set<string>                   funHdrs,          // function:header entries
                                  gloHdrs;          // global symbol:header entries
    map<string, set<string>>      arrRefs;          // function:[array parameter]+ entries
    map<string, vector<string>>   incDeps;          // function:[array parameter]+ entries
    map<uint64_t, vector<string>> strFlds;          // RecordDecl address:struct fields
    map<uint64_t, string>         strAddrs;         // RecordDecl address:struct name
    map<string, set<string>>      signParams;       // function:[signed parameter]+ entries
    map<string, set<string>>      constParams;      // function:[constant parameter]+ entries
    map<string, vector<string>>   paramNames;       // function parameter names

    string outfile;                                 // metadata filename
    string libroot;                                 // library root directory
};

// ------------------------------------------------------------------------------------------------
#endif
