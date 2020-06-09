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
 * preprocessor.cpp
 *
 * TODO: Write a small description and briefly describe assumption (No overloading functions) and
 *       features.
 *
 */
// ------------------------------------------------------------------------------------------------
#include "preprocessor.h"


const char *toolOverview = "FuzzGen Preprocessor " CURRENT_VERSION "\n";

static cl::OptionCategory optCat("Preprocessor options");
static cl::extrahelp      CommonHelp(CommonOptionsParser::HelpMessage);
static cl::extrahelp      MoreHelp(
    /* help message (not helpful at all :P) */
    "This this the preprocessor clang tooling module for FuzzGen.\n"
);

/* command line arguments */
static cl::opt<string> argOutfile(
    "outfile",
    cl::desc("Location to store metadata file"),
    cl::init(DEFAULT_META_FILENAME),
    cl::cat(optCat)
);

static cl::opt<string> arglibroot(
    "library-root",
    cl::desc("Library's root directory"),
    cl::Required,
    cl::cat(optCat)
);

char realPath[PATH_MAX];                            // real path of library's directory



// ------------------------------------------------------------------------------------------------
// Dump an aggregate set (can be vector, list or set) into a string.
//
template<typename T> 
string dump(T aggregate) {
    string str("");


    /* iterate over each element */
    for (typename T::iterator jj=aggregate.begin(); jj!=aggregate.end(); ++jj) {
        str += *jj + " ";
    }

    if (str.length() > 0) {
        str.pop_back();                             // drop last whitespace
    }

    return str;
}



// ------------------------------------------------------------------------------------------------
// Sanitize a module file name (get the real path and drop the library root (if exists)
//
string sanitize(string modname, string libroot) {
    char realPath[PATH_MAX];


    // module name is in the form: external/libhevc/decoder/ihevcd_decode.h:40:8 
    // or in the form: /usr/include/string.h:409:12 <Spelling=/usr/include/string.h:409:28>
    //
    // so drop everything after the first colon
    //
    if (modname.find_first_of(':') != string::npos) {
        modname = modname.erase(modname.find_first_of(':'));
    }


    /* try to get real path from mdule root */
    if (realpath(modname.c_str(), realPath) == NULL) {
        errs() << "[ERROR] Cannot get real path for module '" << modname << "' " ;
        errs() << "(!= '" << realPath << "') .\n";

    } else {
        string real = string(realPath);
        string sanmod;

        /* if path starts with the library root, drop it */
        if (real.compare(0, libroot.length(), libroot) == 0) {
            sanmod = real.substr(libroot.length());

            /* drop the first slash as well */
            if (sanmod[0] == '/') {
                sanmod.erase(0,1);
            }

            return sanmod;
        }
    }

    return "";                                      // something went wrong
}



// ------------------------------------------------------------------------------------------------

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * *                                                                                           * *
 * *                                       VISITOR CLASS                                       * *
 * *                                                                                           * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// ------------------------------------------------------------------------------------------------
// Class constructor. Simply initialize private members.
//
Visitor::Visitor(SourceManager &srcMgr, set<string> &funHdrs, set<string> &gloHdrs,
        map<string, set<string>> &arrRefs, map<uint64_t, vector<string>> &strFlds,
        map<uint64_t, string> &strAddrs,  map<string, set<string>> &signParams,
        map<string, set<string>> &constParams, map<string, vector<string>> &paramNames, 
        string libroot) : 

        srcMgr(srcMgr), funHdrs(funHdrs), gloHdrs(gloHdrs), arrRefs(arrRefs), strFlds(strFlds), 
        strAddrs(strAddrs), signParams(signParams), constParams(constParams),
        paramNames(paramNames), libroot(libroot) {

}



// ------------------------------------------------------------------------------------------------
// Push a global declaration to the globals table.
//
bool Visitor::pushGlobal(NamedDecl *decl, string type) {
    SourceLocation srcLoc = decl->getLocation();
    string mod = srcLoc.printToString(srcMgr);      // get current module's name


    if ((mod = sanitize(mod, libroot)) != "") {     // sanitize module name
        if (decl->getNameAsString() == "") {
            return false;                           // skip empty declarations
        }

        /* we only care about declarations in header files */
        if (mod.substr(mod.find_last_of(".")) == ".h") {
            gloHdrs.insert(decl->getNameAsString() + " " + mod + type);
        }
    }

    return true;
}



// ------------------------------------------------------------------------------------------------
// Callback that is being called when a global variable node is visited. If declaration is global
// save it in globals table.
//
bool Visitor::VisitVarDecl(VarDecl *varDecl) {
    /* check if declaration is global */
    if (varDecl->getParentFunctionOrMethod() == nullptr) {
        pushGlobal(dyn_cast<NamedDecl>(varDecl));
    }

    return true;                                    // do not abort traversal
}



// ------------------------------------------------------------------------------------------------
// Callback that is being called when a struct declaration node is visited. If declaration is
// global save it in globals table.
//
bool Visitor::VisitRecordDecl(RecordDecl *recDecl) {
    /* check if declaration is global */
    if (recDecl->getParentFunctionOrMethod() == nullptr) {
        pushGlobal(dyn_cast<NamedDecl>(recDecl));
    }

    return true;                                    // do not abort traversal
}



// ------------------------------------------------------------------------------------------------
// Callback that is being called when a struct field decllaration node is visited. Associate
// struct field names with RecordDecl objects.
//
bool Visitor::VisitFieldDecl(FieldDecl *fieldDecl) {
    RecordDecl *record = fieldDecl->getParent();    // get struct that field belongs to

    /* if we don't have a "typedef struct", we can also get the struct name */
    if (record->getNameAsString() != "") {
        /* find source code location of declaration */
        SourceLocation srcLoc = record->getLocation();
        string declModule = srcLoc.printToString(srcMgr);

        /* make sure that struct is declared inside library */
        if (sanitize(declModule, libroot) != "") {
            strAddrs[(uint64_t)record] = record->getNameAsString();
        }        

        /* append field to the field vector for this struct */
        // for typedef structs we don't know the name yet that's why we use object's address
        strFlds[(uint64_t)record].push_back(fieldDecl->getNameAsString());
    }

    return true;                                    // do not abort traversal
}



// ------------------------------------------------------------------------------------------------
// Callback that is being called when a typedef declaration node is visited. If declaration is
// global save it in globals table. If declaration corresponds to a struct associate it with
// the struct name.
//
bool Visitor::VisitTypedefDecl(TypedefDecl *tyDecl) {
    /* check if declaration is global */
    if (tyDecl->getParentFunctionOrMethod() == nullptr) {
        // explicitly mark this as typedef
        pushGlobal(dyn_cast<NamedDecl>(tyDecl), " typedef");
    }


    /* check if declaration is a "typedef struct" */
    QualType qualTy = tyDecl->getTypeSourceInfo()->getType();

    /* "dig" into elaborated types (can be >1) in AST until you reach a terminal */
    while (const ElaboratedType *elabTy = dyn_cast<ElaboratedType>(qualTy.getTypePtr())) {
        qualTy = elabTy->desugar();
    }

    /* terminal reached. Check if it's a struct declaration */
    if (strcmp(qualTy->getTypeClassName(), "Record") == 0) {
        const RecordType *recTy   = dyn_cast<RecordType>(qualTy);
        RecordDecl       *recDecl = recTy->getDecl();

        /* find source code location of declaration */
        SourceLocation srcLoc = tyDecl->getLocation();
        string declModule = srcLoc.printToString(srcMgr);

        /* make sure that struct is declared inside library */
        if (sanitize(declModule, libroot) != "") {
            /* associate object's address with name */
            strAddrs[ (uint64_t)recDecl ] = tyDecl->getNameAsString();
        }
    }


    return true;                                    // do not abort traversal
}



// ------------------------------------------------------------------------------------------------
// Callback that is being called when a enum declaration node is visited. If declaration is global
// save it in globals table.
//
bool Visitor::VisitEnumDecl(EnumDecl *enumDecl) {
    /* check if declaration is global */
    if (enumDecl->getParentFunctionOrMethod() == nullptr) {
        pushGlobal(dyn_cast<NamedDecl>(enumDecl));
    }

    return true;                                    // do not abort traversal
}



// ------------------------------------------------------------------------------------------------
// Check whether a (possibly) qualified type is explicitly unsigned or not.
//
bool Visitor::isUnsignedTy(QualType qualTyOrig, string &type) {
    /* find which types is signed integers and which unsigned */
    QualType qualTy = qualTyOrig.getCanonicalType();
    type = "";                                      // final type


    /* if type is composite get the built-in type (i.e., opus_int32 -> int) */
    if (const BuiltinType *biTy = qualTy->getAs<BuiltinType>()) {
        type = string(biTy->getName(LangOptions()));

        if (biTy->isUnsignedIntegerType()) {
            return true;                            // type is unsigned
        }

    } else {
        type = QualType::getAsString(qualTyOrig.split(), LangOptions());

        if (qualTyOrig->isUnsignedIntegerType()) {
            return true;                            // type is unsigned
        }
    }
                 

    /* check if the (raw) type string contains the word "unsigned" */
    if ((type.find("int")    != string::npos ||
         type.find("char")   != string::npos ||
         type.find("float")  != string::npos ||
         type.find("double") != string::npos)
        &&
        (type.find("unsigned") != string::npos)) {

            return true;                            // type is unsigned
    }

    return false;                                   // type is signed
}



// ------------------------------------------------------------------------------------------------
// Callback that is being called when a function declation is visited. Because AST nodes are
// visited in preorder Depth First traversal, any Stmt is being visited belongs to the last
// function that has been declared. So each time we encounter an Stmt, we can find in which
// function belongs to just by remembering the latest function declaration.
//
bool Visitor::VisitFunctionDecl(FunctionDecl *funcDecl)
{
    SourceLocation srcLoc = funcDecl->getLocation();

    curFun = funcDecl->getNameAsString();           // get current function's name
    curMod = srcLoc.printToString(srcMgr);          // get current module's name


    if ((curMod = sanitize(curMod, libroot)) == "") {
        return true;
    }

    /* we only care about function declarations in header files */
    if (curMod.substr(curMod.find_last_of(".")) == ".h") {
        funHdrs.insert(curFun + " " + curMod);
    }

    // if (!funcDecl->hasBody()) return true;
    param.clear();


    for (FunctionDecl::param_const_iterator ii=funcDecl->param_begin();
            ii!=funcDecl->param_end(); ++ii) {
        string type = "";                           // final type


        param[(*ii)->getNameAsString()] = 0;        // hold all parameter names
        paramNames[curFun].push_back((*ii)->getNameAsString());


        /* find which types is signed integers and which unsigned */
        if (!isUnsignedTy((*ii)->getType(), type)) {
            signParams[curFun].insert((*ii)->getNameAsString());
        }

        /* check if the (raw) type is constant */
        if (type.find("const") != string::npos) {   // qualTy->isConstant()
            constParams[curFun].insert((*ii)->getNameAsString());
        }
    }


    /* check if return value is signed or unsigned */
    string type = "";                               // this doesn't matter here

    if (!isUnsignedTy(funcDecl->getReturnType(), type)) {       
        signParams[curFun].insert("$RETVAL$");
    }


    return true;                                    // do not abort traversal
}



// ------------------------------------------------------------------------------------------------
// Callback that is being called when a statement node is visited. The goal here, is to detect
// whether the function arguments (if any) that are being used as arrays (note that aliases can't
// be detected). Consider the following scenarios:
//
// [1]. Simple arrays: "p[1] = 2". In this case the generated AST will be:
//
//      ArraySubscriptExpr 0x50610b0 'int' lvalue
//      |-ImplicitCastExpr 0x5061098 'int *' <LValueToRValue>
//      | `-DeclRefExpr 0x5061050 'int *' lvalue ParmVar 0x505f100 'p' 'int *'
//      `-IntegerLiteral 0x5061078 'int' 1
//
//
// [2]. Nested arrays: "p[ p[3] ] = 4". Here AST will be:
//
//      ArraySubscriptExpr 0x5061200 'int' lvalue
//      |-ImplicitCastExpr 0x50611d0 'int *' <LValueToRValue>
//      | `-DeclRefExpr 0x5061120 'int *' lvalue ParmVar 0x505f100 'p' 'int *'
//      `-ImplicitCastExpr 0x50611e8 'int' <LValueToRValue>
//        `-ArraySubscriptExpr 0x50611a8 'int' lvalue
//          |-ImplicitCastExpr 0x5061190 'int *' <LValueToRValue>
//          | `-DeclRefExpr 0x5061148 'int *' lvalue ParmVar 0x505f100 'p' 'int *'
//          `-IntegerLiteral 0x5061170 'int' 3
//
//
// [3]. Multidimensional arrays: "q[5][6][7] = 8", with the following AST:
//
//      ArraySubscriptExpr 0x5061390 'int' lvalue
//      |-ImplicitCastExpr 0x5061378 'int *' <LValueToRValue>
//      | `-ArraySubscriptExpr 0x5061330 'int *' lvalue
//      |   |-ImplicitCastExpr 0x5061318 'int **' <LValueToRValue>
//      |   | `-ArraySubscriptExpr 0x50612d0 'int **' lvalue
//      |   |   |-ImplicitCastExpr 0x50612b8 'int ***' <LValueToRValue>
//      |   |   | `-DeclRefExpr 0x5061270 'int ***' lvalue Var 0x5060fd8 'q' 'int ***'
//      |   |   `-IntegerLiteral 0x5061298 'int' 5
//      |   `-IntegerLiteral 0x50612f8 'int' 6
//      `-IntegerLiteral 0x5061358 'int' 7
//
//      Here, "q[5][6][7]" is treated as "x[7]", where "x = q[5][6]" and "q[5][6]" is treated as
//      y[6], where "y = q[5]".
//
// All of the above cases are reduced to single array references, so all we have to do is to look
// for the sequence: ArraySubscriptExpr -> ImplicitCastExpr -> DeclRefExpr
//
// Alternatively we could use Matchers, but there's no need here, as the sequence that we look for
// is simple.
//
bool Visitor::VisitStmt(Stmt *stmt) {
    // errs() << "===== Dumping Statement:" << stmt->getStmtClassName() << "\n";
    // stmt->dumpColor();

    /* we only care about ArraySubscriptExpr */
    if (isa<ArraySubscriptExpr>(stmt)) {

        /*
         * from clang doc: An array access can be written as A[4]
         * getBase() returns "A" and getIdx() returns "4"
         */
        const ArraySubscriptExpr *arr = dyn_cast<ArraySubscriptExpr>(stmt);
        const Expr *base = arr->getBase();

        if (isa<ImplicitCastExpr>(base)) {
            const ImplicitCastExpr *impl = dyn_cast<ImplicitCastExpr>(base);
            const Expr *expr = impl->getSubExpr();

            if (isa<DeclRefExpr>(expr)) {
                const DeclRefExpr *decl = dyn_cast<DeclRefExpr>(expr);
                DeclarationNameInfo nam = decl->getNameInfo();

                /* check if array is a function parameter */
                if (param.find(nam.getAsString()) != param.end()) {
                    param[nam.getAsString()] = 1;

                    arrRefs[ curFun ].insert(nam.getAsString());
                }
            }
        }
    }

    return true;                                    // do not abort traversal
}



// ------------------------------------------------------------------------------------------------

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * *                                                                                           * *
 * *                                    AST PROCESSOR CLASS                                    * *
 * *                                                                                           * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// ------------------------------------------------------------------------------------------------
// Class constructor. Simply initialize private members.
//
ASTProcessor::ASTProcessor(set<string> &funHdrs, set<string> &gloHdrs,
        map<string, set<string>> &arrRefs, map<uint64_t, vector<string>> &strFlds,
        map<uint64_t, string> &strAddrs, map<string, set<string>> &signParams,
        map<string, set<string>> &constParams, map<string, vector<string>> &paramNames, 
        string libroot) : 

        funHdrs(funHdrs), gloHdrs(gloHdrs), arrRefs(arrRefs), strFlds(strFlds), strAddrs(strAddrs),
        signParams(signParams), constParams(constParams), paramNames(paramNames), 
        libroot(libroot) { 

}


// ------------------------------------------------------------------------------------------------
// Callback, after the entire translation unit's AST has been parsed.
//
void ASTProcessor::HandleTranslationUnit(ASTContext& context) {
    // NOTE: Don't use HandleTopLevelDecl() as AST parsing is still on the fly
    SourceManager &srcMgr = context.getSourceManager();

    /* creatte an AST visitor and start traversing the AST */
    Visitor visitor(srcMgr, funHdrs, gloHdrs, arrRefs, strFlds, strAddrs, signParams, constParams,
                    paramNames, libroot);

    visitor.TraverseDecl(context.getTranslationUnitDecl());
}



// ------------------------------------------------------------------------------------------------

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * *                                                                                           * *
 * *                                 INCLUDES PROCESSOR CLASS                                  * *
 * *                                                                                           * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// ------------------------------------------------------------------------------------------------
// Class constructor. Simply initialize private members.
//
IncludesProcessor::IncludesProcessor(CompilerInstance& compInst, map<string, vector<string>> &incl,
        string libroot) : 
        compInst(compInst), incDeps(incl), libroot(libroot) {
}



// ------------------------------------------------------------------------------------------------
// When an #include (or #import) directive is encountered this callback is invoked.
// (we assume that there are no #import headers).
//
void IncludesProcessor::InclusionDirective(SourceLocation HashLoc, const Token &IncludeTok,
        StringRef FileName, bool IsAngled, CharSourceRange FilenameRange, const FileEntry *File,
        StringRef SearchPath, StringRef RelativePath, const clang::Module *Imported,
        SrcMgr::CharacteristicKind FileType) {

    /* ignore errors when an include cannot be found */
    compInst.getPreprocessor().SetSuppressIncludeNotFoundError(true);

    /* we don't care about standard <> includes */
    if (IsAngled) return;

    /* get current module's name */
    SourceManager &srcMgr = compInst.getSourceManager();
    string mod = HashLoc.printToString(srcMgr);

    if ((mod = sanitize(mod, libroot)) != "") {
        /* add header dependency */
        incDeps[ mod ].push_back(FileName);
    }
}



// ------------------------------------------------------------------------------------------------

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * *                                                                                           * *
 * *                                FUZZGEN PREPROCESSOR CLASS                                 * *
 * *                                                                                           * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// ------------------------------------------------------------------------------------------------
// Class constructor. Simply give a default filename for metadata file.
//
FuzzGenPreprocessor::FuzzGenPreprocessor() : 
        outfile(argOutfile), libroot(string(realPath)) {
}



// ------------------------------------------------------------------------------------------------
// Create the AST consumer object.
//  
unique_ptr<ASTConsumer> FuzzGenPreprocessor::CreateASTConsumer(CompilerInstance &compInst, 
        StringRef ParsedTemplates) {
 
    /* create the callback to process #include directives */
    compInst.getPreprocessor().addPPCallbacks(
            unique_ptr<PPCallbacks>(new IncludesProcessor(compInst, incDeps, libroot)));

    return make_unique<ASTProcessor>(funHdrs, gloHdrs, arrRefs, strFlds, strAddrs, signParams,
                                     constParams, paramNames, libroot);
}



// ------------------------------------------------------------------------------------------------
// Before processing starts, display a message to the user.
//
bool FuzzGenPreprocessor::BeginSourceFileAction(CompilerInstance &compInst) {
    /* get all input files (we 're only interested in the 1st one) */
    vector<FrontendInputFile> Inputs = compInst.getFrontendOpts().Inputs;
    string filename = Inputs[0].getFile();


    if ((filename = sanitize(filename, libroot)) != "") {
            errs() << "[INFO] Parsing '" << filename << "' ...\n";

        if (Inputs.size() != 1) {                       // just in case ;)
            errs() << "[WARN] There are " << Inputs.size() << " distinct inputs\n";
        }

        
        /* silent any compiler errors after syntax analysis */
        compInst.getDiagnostics().setClient(new FuzzGenDiagnosticConsumer(), true);
    }

    return true;                                // do not abort processing
}



// ------------------------------------------------------------------------------------------------
// After processing has finished, dump headers globals and array references to the file. Note that
// when -j flag is used multiple threads can write at the same file, so file locks are needed.
// Because ofstream doesn't support locks, standard UNIX I/O is used instead.
//
// UPDATE: The aforementioned problem with mutual exclusion exists only in the (old) plugin 
//         version. In "tooling" version we don't have this problem.
//         
void FuzzGenPreprocessor::EndSourceFileAction() {
    ostringstream out;


    // there's no compInst at this point, so use errs()
    errs() << "[INFO] Appending data to '" << outfile + "' ...\n";

    /* write headers for each function (if any) */
    if (funHdrs.size() > 0) {
        out << "# ================ #" << funHdrs.size() << " FUNCTIONS ================ #\n";
        out << "@functionhdrs\n";

        for (set<string>::iterator ii=funHdrs.begin(); ii!=funHdrs.end(); ++ii) {
            out << *ii << "\n";
        }

        out << "\n";
    }


    /* write globals for each function (if any) */
    if (gloHdrs.size() > 0) {
        out << "# ================ #" << gloHdrs.size() << " GLOBALS ================ #\n";
        out << "@globalhdrs\n";

        for (set<string>::iterator ii=gloHdrs.begin(); ii!=gloHdrs.end(); ++ii) {
            out << *ii << "\n";
        }

        out << "\n";
    }


    /* write array parameters for each function */
    if (paramNames.size() > 0) {
        out << "# ================ #" << paramNames.size() << " PARAMETERS ================ #\n";
        out << "@params\n";


        for (map<string, vector<string>>::iterator ii=paramNames.begin(); ii!=paramNames.end(); 
                ++ii) {

            out << ii->first << "\t" << dump(ii->second) << "\n";
        }

        out << "\n";
    }


    /* write array parameters for each function */
    if (arrRefs.size() > 0) {
        out << "# ================ #" << arrRefs.size() << " ARRAYS ================ #\n";
        out << "@arrayrefs\n";

        for (map<string, set<string>>::iterator ii=arrRefs.begin(); ii!=arrRefs.end(); ++ii) {
            out << ii->first << "\t" << dump(ii->second) << "\n";
        }

        out << "\n";
    }


    /* write #include dependencies for each file */
    if (incDeps.size() > 0) {
        out << "# ================ #" << incDeps.size() << " INCLUDES ================ #\n";
        out << "@includedeps\n";

        for (map<string, vector<string>>::iterator ii=incDeps.begin(); ii!=incDeps.end(); ++ii) {       
            out << ii->first << "\t" << dump(ii->second) << "\n";
        }

        out << "\n";
    }


    /* write struct fields for each file */
    if (strAddrs.size() > 0) {
        out << "# ================ #" << strAddrs.size() << " STRUCTS ================ #\n";
        out << "@structdecls\n";


        // we assume that "strAddrs.size() == strFlds.size()" and 
        // strAddrs[ii->first] always exists 

        for (map<uint64_t, vector<string>>::iterator ii=strFlds.begin(); ii!=strFlds.end(); ++ii) {
            string         structName = strAddrs[ii->first];

            out << structName << "\t" << dump(ii->second) << "\n";
        }

        out << "\n";
    }


    /* write array parameters for each function */
    if (signParams.size() > 0) {
        out << "# ================ #" << signParams.size() 
            << " SIGNED PARAMETERS ================ #\n";
        out << "@signedparams\n";


        for (map<string, set<string>>::iterator ii=signParams.begin(); ii!=signParams.end(); 
                ++ii) {

            out << ii->first << "\t" << dump(ii->second) << "\n";
        }

        out << "\n";        
    }


    /* write array parameters for each function */
    if (constParams.size() > 0) {
        out << "# ================ #" << constParams.size() 
            << " CONST PARAMETERS ================ #\n";
        out << "@constparams\n";


        for (map<string, set<string>>::iterator ii=constParams.begin(); ii!=constParams.end(); 
                ++ii) {

            out << ii->first << "\t" << dump(ii->second) << "\n";
        }

        out << "\n";        
    }


    /* flush string stream to file */
    struct flock fl = {
        F_WRLCK,                                // l_type
        SEEK_SET,                               // l_whence
        0,                                      // l_start
        0,                                      // l_len (till EOF)
        getpid()                                // l_pid
    };

    int fd = open(outfile.c_str(), O_WRONLY | O_APPEND | O_CREAT, 0644);


    if (fd == -1) {
        errs() << "[ERROR] Cannot open file: " << strerror(errno) << "\n";
        return;
    }

    /* get an exclusive lock */
    if (fcntl(fd, F_SETLKW, &fl) == -1) {
        errs() << "[ERROR] Cannot acquire lock: " << strerror(errno) << "\n";
        close(fd);
        return;
    }

    /* write string stream to file */
    if (write(fd, out.str().c_str(), out.tellp()) != out.tellp()) {
        errs() << "[ERROR] Cannot write to file: " << strerror(errno) << "\n";
        close(fd);
        return;
    }

    fl.l_type = F_UNLCK;                        // release lock

    if (fcntl(fd, F_SETLK, &fl) == -1) {
        errs() << "[ERROR] Cannot release lock: " << strerror(errno) << "\n";
    }

    close(fd);

    errs() << "[INFO] Appending completed.\n";
}



// ------------------------------------------------------------------------------------------------

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * *                                                                                           * *
 * *                                       MAIN FUNCTION                                       * *
 * *                                                                                           * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// ------------------------------------------------------------------------------------------------
// Get current date and time (copied from common.cpp).
//
std::string now(void) {
    time_t    t   = time(0);
    struct tm now = *localtime(&t);
    char      time[64];


    strftime(time, 64, "%d-%m-%Y %X %Z", &now);

    return string(time);
}



// ------------------------------------------------------------------------------------------------
// Entry point for FuzzGen Preprocessor
//
int main(int argc, const char *argv[]) {
    errs() << "[INFO] Starting FuzzGen Preprocessor " << CURRENT_VERSION
           << " at " << now() << "\n";


    /* print a stack trace in case of a signal */
    sys::PrintStackTraceOnErrorSignal(argv[0], false);
    PrettyStackTraceProgram stTrace(argc, argv);


    errs() << "[INFO] Please ignore the following errors " 
           << "(failure to load a compilation database)...\n";

    /* parse command line arguments */
    CommonOptionsParser OptionsParser(argc, argv, optCat, cl::OneOrMore, toolOverview);


    /* try to get real path from library root */
    if (realpath(arglibroot.c_str(), realPath) == NULL) {
        errs() << "[ERROR] Cannot get library's real path! Abort.\n";
        return 0;
    }

    errs() << "[INFO] Library full path is '" << realPath << "'\n";
    

    /* ensure that file is empty */
    ofstream out;
    out.open(argOutfile, ofstream::out | ofstream::trunc);
    out << banner << "\n"
        << "# Version: " << CURRENT_VERSION << "\n"
        << "#\n"
        << "# ~~~ THIS FILE HAS BEEN GENERATED AUTOMATICALLY BY *FUZZGEN PREPROCESSOR* AT: " 
        << now() << " ~~~\n"
        << "#\n"
        << "#\n\n";
    out.close();


    /* create clang tooling object */
    ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getSourcePathList());

    /* run the AST parser on the file */
    if (!Tool.run(newFrontendActionFactory<FuzzGenPreprocessor>().get())) {
        // clang tooling failed (that's due to compilation errors, so we're ok)
    }


    return 0;
}
    
// ------------------------------------------------------------------------------------------------