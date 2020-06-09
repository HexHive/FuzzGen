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
 * dig.cpp
 *
 * TODO: Write a small description.
 *
 */
// ------------------------------------------------------------------------------------------------
#include "dig.h"



// ------------------------------------------------------------------------------------------------

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * *                                                                                           * *
 * *                                         DIG CLASS                                         * *
 * *                                                                                           * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// ------------------------------------------------------------------------------------------------
// Class constructor. Initialize class members.
//
Dig::Dig(const Module *module, Context *ctx) :
        ctx(ctx), module(module), magic(nullptr) {

    info(v2) << "Dig module started.\n";
}



// ------------------------------------------------------------------------------------------------
// Class destructor.
//
Dig::~Dig(void) {
    // TODO: release allocated objects
}



// ------------------------------------------------------------------------------------------------
// Check if an argument represents an array. IR doesn't have this information, so look it up from
// library's metadata.
//
// TODO: make this function a friend with Magic class
//
inline bool Dig::isArray(const Argument *arg) {
    if (arg == nullptr) {                           // base check
        return false;
    }

    return ctx->arrayRef[arg->getParent()->getName()].find(arg->getName()) !=
           ctx->arrayRef[arg->getParent()->getName()].end();
}



// ------------------------------------------------------------------------------------------------
// Dig a data type until you reach its basic construction. This function is recursive. If dig
// fails, function returns false.
//
// Some notes regarding structs:
//  [1]. Structs have the alignment of their widest scalar member
//  [2]. Structs have no leading padding
//  [3]. Structs are aligned in arrays
//  [4]. Nested structs have the alignment of longest scalar
//
// Some things that are not supported (when something is not supported, don't fuzz it)
//  [1]. Bit fields
//  [2]. Unions
//
bool Dig::digInto(Argument *A, Type *type, interwork::Element *elt, uint64_t off, int deep,
        bool byval) {

    DataLayout dataLayout(module);

    // dataLayout.reset("e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128");
    //                  "e-m:e-p:32:32-i64:64-v128:64:128-a:0:32-n32-S64"

    if (!type->isVoidTy()) {                        // base check to avoid exceptions
        elt->size = dataLayout.getTypeAllocSize(type);
    }

    elt->nsz      = 1;
    elt->isBaseTy = true;


    /* loop gets executed once for basic types */
    for (elt->nptr[elt->nptrIdx]=0; ; elt->isBaseTy=false) {

        // ------------------------------------------------------------------------------
        if (type->isVoidTy()) {
            info(v2) << "Encounter a void type.\n";

            elt->baseType = interwork::Ty_void;
            elt->attr = new interwork::Attributes<int>(ATTR_DEAD, "int");
        }

        // ------------------------------------------------------------------------------
        else if (type->isIntegerTy()) {
            // LLVM has eliminated the distinction between signed and unsigned integer types
            // (http://nondot.org/~sabre/LLVMNotes/TypeSystemChanges.txt)

            if (magic) magic->clear();

            switch (type->getIntegerBitWidth()) {
              case 8:
                elt->baseType = interwork::Ty_i8;
                
                /*
                 * Fix: void* is interpreted as i8*. When we cast a struct to void*, our 
                 *      predefineds, will be i8. For now, we make it i64, to catch all
                 *      predefined values.
                 */
                if (magic) elt->attr = magic->do_magic(*A, argTy, "int64_t");
                break;

              case 16:
                elt->baseType = interwork::Ty_i16;

                if (magic) elt->attr = magic->do_magic(*A, argTy, "int16_t");
                break;

              case 32:
                elt->baseType = interwork::Ty_i32;
                
                if (magic) elt->attr = magic->do_magic(*A, argTy, "int32_t");
                break;

              case 64:
                elt->baseType = interwork::Ty_i64;
                
                if (magic) elt->attr = magic->do_magic(*A, argTy, "int64_t"); 
            }

            if (!magic) {                           // if magic is disable give a dead argument
                elt->attr = new interwork::Attributes<int>(ATTR_DEAD, "int");
            }
        }

        // ------------------------------------------------------------------------------
        else if (type->isFloatTy()) {
            elt->baseType = interwork::Ty_float;

            if (magic) {
                magic->clear();  
                elt->attr = magic->do_magic(*A, argTy, "float");
            } else {
                elt->attr = new interwork::Attributes<int>(ATTR_DEAD, "float");    
            }
        }

        // ------------------------------------------------------------------------------
        else if (type->isDoubleTy()) {
            elt->baseType = interwork::Ty_double;

            if (magic) {
                magic->clear();  
                elt->attr = magic->do_magic(*A, argTy, "double");
            } else {
                elt->attr = new interwork::Attributes<int>(ATTR_DEAD, "double");    
            }
        }

        // ------------------------------------------------------------------------------
        else if (type->isPointerTy()) {
            info(v2) << "Encounter a pointer: " << *type << ". Digging into it...\n";

            /* pointers are SequentialType and thus have 1 ContainedType */
            type = dyn_cast<PointerType>(type)->getElementType();
            ++elt->nptr[elt->nptrIdx];
            continue;                               // move on!
        }

        // ------------------------------------------------------------------------------
        else if (type->isArrayTy()) {
            info(v2) << "Encounter an array: " << *type << ". Digging into it...\n";

            /* arrays are SequentialType and thus have 1 ContainedTypes */
            ArrayType *arr = dyn_cast<ArrayType>(type);


            /* treat multi-dimensional arrays as a single dimensional one */
            elt->nsz *= arr->getNumElements();
            elt->sz.push_back( arr->getNumElements() );

            type = arr->getElementType();
            elt->nptrIdx = 1;

            continue;                               // move on!
        }

        // ------------------------------------------------------------------------------
        else if (type->isStructTy()) {
            info(v2) << "Encounter a struct: " << *type << ". Digging into it...\n";


            vector<StructType*> V = module->getIdentifiedStructTypes();
            list<interwork::Element*> strct;
            uint32_t i;
            int      attr = 0;


            /* base check. If struct is opaque (forward declared), abort */
            StructType *stTy = dyn_cast<StructType>(type);
            if (stTy->isOpaque()) {
                warning() << "Opaque struct! Dig failed :(\n";

                elt->attr = new interwork::Attributes<int>(ATTR_DEAD, "struct");
                elt->baseType   = interwork::Ty_struct;
                elt->structName = type->getStructName();
                elt->isBaseTy   = false;
                break;
            }

            /* bogus attr (can't be null) */
            elt->attr = new interwork::Attributes<int>(attr, "struct");

            /* search for this struct using its name */

            /* OPT: Make a hash table to avoid linear search each time */
            for (i=0; i<V.size(); ++i) {
                if (type->getStructName() == V[i]->getName()) break;
            }

            if (i >= V.size()) break;               // this should never happen, but leave it for now

            elt->baseType   = interwork::Ty_struct;
            elt->structName = V[i]->getName();
            elt->fieldName  = "";
            elt->off        = off;                  // start from current point
            elt->isBaseTy   = false;


            //if (elt->nsz > 1 || (elt->nptrs() > 0 && isArray(A))) {
            if (elt->nptrs() > 0 && isArray(A)) {
                attr = ATTR_ARRAY;
            }

            /* if original argument is byval, set attribute */
            if (byval) attr |= ATTR_BYVAL;


            /* bogus attr (can't be null) */
            elt->attr = new interwork::Attributes<int>(attr, "struct");


            /*
             * To avoid infinity loops, make sure that each derived struct is visited once.
             * For instance lists, have *next pointers that point to structs of the same type.
             *
             * Now you can loop up to k times to catch cases like lists (k = constant).
             */
            if (elt->nptrs() > 0) {

                if (visited.find(V[i]->getName()) == visited.end() || visited[V[i]->getName()] < 1) {
                    /* if struct not visited, mark it */
                    ++visited[V[i]->getName()];
                }
                else {
                    /* set it to NULL, to avoid infinity loops */
                    elt->attr->addAttr(ATTR_NULLPTR);

                    info(v2) << "Struct is visited. skip\n";
                    break;
                }
            }

            const StructLayout *sl = dataLayout.getStructLayout(V[i]);


            /* for each element */
            //  for (StructType::element_iterator ii=V[i]->element_begin();
            //           ii!=V[i]->element_end(); ++ii) {
            for(size_t k=0; k<V[i]->getNumElements(); ++k) {
                //Type *eltTy = *ii;
                Type *eltTy = V[i]->getElementType(k);

                /*
                 * A big problem here, is that IR omits names of the struct elements: *
                 *    %struct.foo = type { i16, [16 x i16], i32, i8*, %struct.bar* }
                 *    %struct.bar = type { i16, void (i8*, i8*)* }
                 */

                interwork::Element *subElt = new interwork::Element();

                /* elements have no name, so they inherit parent's argument name */
                subElt->tyStr      = getTypeStr(eltTy);
                subElt->name       = A ? A->getName() : "$NONAME$";
                subElt->structName = elt->structName;
                subElt->parent     = elt;

                // structName starts with "struct.". Based on index lookup field name
                if(ctx->strFields.find(stripStructName(elt->structName)) == ctx->strFields.end()) {
                    fatal() << "'" << elt->structName << "' is not in the metadata file.\n";
                    
                    ctx->reportIssue("Struct '" + elt->structName + "' is not in the metadata "
                                     "file. Please update file accordingly.");

                    //return false;
                    subElt->fieldName = "UNKNOWN";
                }
                else {

                    /* make sure that struct has all fields defined in metadata */
                    if (0 && ctx->strFields[stripStructName(elt->structName)].size() <= k) {
                        fatal() << "Struct '" << elt->structName << "' has " << k
                                << " elements but strFields has " << ctx->strFields[stripStructName(elt->structName)].size()
                                << " registered.\n";

                        throw FuzzGenException("digInto(): A struct field is missing. "
                                               "Please make sure that metadata file is correct");
                    } else if (ctx->strFields[stripStructName(elt->structName)].size() <= k) {
                    
                        subElt->fieldName = "$__extra__field__";
                    } else {

                        subElt->fieldName  = ctx->strFields[elt->structName.substr(7)][k];
                    }
                }

                subElt->idx        = k;
                subElt->size       = dataLayout.getTypeAllocSize(eltTy);
                subElt->off        = off + sl->getElementOffset(k);
                subElt->nsz        = 0;

                info(v2) << "----------------------------------------------------------------\n";
                info(v2) << "Iterating over element: " << *eltTy
                         << " at offset " << subElt->off << "\n";

                /* recursively analyze element */
                info(v2) << "  * Entering digInto(" << deep+1 << ", " << subElt->off << ")\n";

                structOff.push_back(k);             // prepare offset of magic()

                if (!digInto(A, eltTy, static_cast<interwork::Element *>(subElt), subElt->off,
                        deep+1, 0)) {
                    return false;                   // propagate failure
                }

                structOff.pop_back();

                strct.push_back(subElt);            // add element to the subelements
            }

            elt->subElements = strct;
        }

        // ------------------------------------------------------------------------------
        else if (type->isFunctionTy()) {
            elt->baseType = interwork::Ty_funcptr;
            elt->isBaseTy = true;                   // yes it's basic type
            elt->nptr[elt->nptrIdx]--;              // drop the pointer that you added before


            info(v2) << "Encounter a function pointer: " << *type << ". Digging into it...\n";

            /*
             * When a function uses a function pointer we have 3 possible options:
             *      [1]. We can simply set pointer to NULL
             *      [2]. We can set pointer to an arbitrary value (e.g., 0xdeadbeef)
             *      [3]. We can set pointer to a valid function (we have all the type 
             *           information that we want from the IR, so we can easily declare
             *           such a function) and fuzz the return value.
             *
             * We will only consider [3], as it can be combined with the external module.
             */

            if (type->isFunctionVarArg()) {
                fatal() << "Variadic functions pointers are not supported. Setting it to NULL\n";
                
                /* fall back to option [1] */
                elt->attr = new interwork::Attributes<uint8_t>(ATTR_NULLPTR, "");

                return true;
            }


            /* initialize function pointer object */
            elt->funcptr = new interwork::FunctionPtr();
            elt->attr    = new interwork::Attributes<int>(ATTR_FUNCPTR, "");

            Magic *magic_bkp = magic;               // backup magic object
            magic = nullptr;                        // function pointers can't have magic
            
       
            /* first subtype always corresponds to return value */
            Type *retValTy       = type->getContainedType(0);
            elt->funcptr->retval = new interwork::Argument();

            info(v2) << "Return Value: " << *retValTy << "\n";

            /* dig into return value */ 
            if (!digInto(A, retValTy, static_cast<interwork::Argument *>(elt->funcptr->retval), 0,
                    deep+1, 0)) {
                magic = magic_bkp;                  // restore magic
                return false;                       // propagate failure
            }


            /* follow [3], and fuzz the return value. So simple ;) */ 
            elt->funcptr->retval->attr->addAttr(ATTR_RANDOM);           
            // elt->attr->addRef("foo");            // to give a name to the function pointer

            /* do the same for the parameters */
            for (unsigned i=0; i<type->getFunctionNumParams(); ++i) {
                interwork::Argument *param   = new interwork::Argument();
                Type                *paramTy = type->getFunctionParamType(i);

                
                info(v2) << "Parameter #" << i+1 << " : " << *paramTy << "\n";
                
                param->idx = i + 1;                 // set index

                /* analyze the type of each parameter */
                
                // NOTE: We don't really need to digInto structs, so we ignore subElements
                if (!digInto(A, paramTy, static_cast<interwork::Element *>(param), 0, deep+1, 0)) {
                    magic = magic_bkp;              // restore magic
                    return false;                   // propagate failure
                }

                elt->funcptr->params.push_back(param);
            }

            magic = magic_bkp;                      // restore magic
        }

        // ------------------------------------------------------------------------------
        else {
            warning() << "Unknown type '" << *type << "' (TypeID: " << type->getTypeID() << ")\n";
            return false;                           // failure
        }

        break;                                      // break loop
    }

    return true;                                    // success!
}



// ------------------------------------------------------------------------------------------------
// Wrapper around digInto().
//
interwork::Argument *Dig::digType(Argument &funcArg, Type *type, bool doMagic) {
    argTy = funcArg.getType();


    if (type) {
        argTy = type;
    }

    if (doMagic) {
        magic = new Magic(ctx, structOff);
    }


    info(v2) << "Analyzing argument '" << funcArg.getName() << "' of type '" << *argTy
             << "'...\n";

    interwork::Argument *arg = new interwork::Argument();
    arg->name  = funcArg.getName();
    arg->idx   = funcArg.getArgNo();
    arg->tyStr = getTypeStr(argTy);

    string funcName = funcArg.getParent()->getName() ;


    if (arg->name == "") {
        if (ctx->paramNames.find(funcName) != ctx->paramNames.end() &&
            ctx->paramNames[funcName].size() > arg->idx) {

                /* get parameter name */
                arg->name = ctx->paramNames[funcName][arg->idx];            

        } else {
            arg->name = "$NOT_FOUND";
            //throw FuzzGenException("digType(): Parameter name does not found. Check metadata file");
        }
    }

    /* check if argument is signed. We use clang as LLVM treats all integers as unsigned */
    if (ctx->signParam.find(funcName)            != ctx->signParam.end() &&
        ctx->signParam[funcName].find(arg->name) != ctx->signParam[funcName].end()) {

            info(v3) << "Argument is signed.\n";   
            arg->isSigned = 1;
    } else {
        arg->isSigned = 0;
    }

    /* check if argument is const (needed to silent compiler errors) */
    if (ctx->constParam.find(funcName)            != ctx->constParam.end() &&
        ctx->constParam[funcName].find(arg->name) != ctx->constParam[funcName].end()) {

            info(v3) << "Argument is constant.\n";   
            arg->isConst = 1;
    } else {
        arg->isConst = 0;
    }

    visited.clear();                                // clear visited nodes
    structOff.clear();                              // clear deque

    /* do the actual type "dig" */
    if (!digInto(&funcArg, argTy, static_cast<interwork::Argument*>(arg), 0, 0,
                    funcArg.hasByValAttr()) ) {//|| arg->attr->flags & ATTR_FAILURE) {

        fatal() << "digInto() failed. Much Sad. Current function is discarded.\n";

        return nullptr;
    }

    return arg;
}



// ------------------------------------------------------------------------------------------------
// Wrapper around digInto() *for return values).
//
interwork::Argument *Dig::digRetValType(Type *type) {
    argTy = type;
    magic = nullptr;


    info(v2) << "Analyzing return value of type '" << *argTy << "'...\n";

    interwork::Argument *arg = new interwork::Argument();
    arg->name  = "$RETVAL$";
    arg->idx   = -1;
    arg->tyStr = getTypeStr(argTy);

    visited.clear();                                // clear visited nodes
    structOff.clear();                              // clear deque

    
    /* do the actual type "dig" */
    if (!digInto(nullptr, argTy, static_cast<interwork::Argument*>(arg), 0, 0,
                    false) ) {//|| arg->attr->flags & ATTR_FAILURE) {

        fatal() << "digInto() failed on return value. Much Sad. Current function is discarded.\n";

        return nullptr;
    }

    return arg;
}



// ------------------------------------------------------------------------------------------------
// Get the pure struct type of a type (if exists).
//
Type *Dig::getStructTy(Type *type) {
    Type *structTy = type;

    /* skip all pointers first */
    while (structTy->isPointerTy()) {
        structTy = dyn_cast<PointerType>(structTy)->getElementType();
    }

    /* if the resulting type is a struct retyrn it */
    return structTy->isStructTy() ? structTy : nullptr;
}



// ------------------------------------------------------------------------------------------------
// Get the struct name of a type (if exists).
//
string Dig::getStructName(Type *type) {
    Type *structTy = getStructTy(type);             // get the pure struct type first

    /* if struct type exists, return its name */
    return string(structTy ? structTy->getStructName() : "");
}



// ------------------------------------------------------------------------------------------------
// Strip a fully qualified llvm struct name (e.g. "struct.foo") to get the actual name of the
// struct as declared in the source file (e.g. "foo").
//
string Dig::stripStructName(string fullname) {

    // TODO: Deal with namespaces such as "struct.android::SoftGSM"

    return fullname.substr(7);
}




// ------------------------------------------------------------------------------------------------
// Get the number of pointer indirections for a type.
//
unsigned Dig::getStructPtrs(Type *type) {
    Type     *structTy = type;
    unsigned nptr      = 0;

    /* simply count all pointers */
    while (structTy->isPointerTy()) {
        structTy = dyn_cast<PointerType>(structTy)->getElementType();
        ++nptr;
    }

    return nptr;
}



// ------------------------------------------------------------------------------------------------
// Get type as a string.
//
string Dig::getTypeStr(Type *type) {
    string             tyStr;                       // store type here
    raw_string_ostream raw(tyStr);                  // ostringstream equivalent


    type->print(raw);                               // print type in stream
    
    return raw.str();                               // get it as a string
}



// ------------------------------------------------------------------------------------------------
// Get base type (i.e., ignore pointers) as a string.
//
string Dig::getBaseTypeStr(Type *type) {
    string tyBase = "";
  

    for(char &ch : getTypeStr(type)) {
        if (ch != '*') tyBase += ch;                // strcpy and ignore '*'
    }

    
    return tyBase;                                  // return base type
}



// ------------------------------------------------------------------------------------------------

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * *                                                                                           * *
 * *                                     DIG WRAPPER CLASS                                     * *
 * *                                                                                           * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// ------------------------------------------------------------------------------------------------
// Globals
//
char DigWrapper::ID = 1;



// ------------------------------------------------------------------------------------------------
// Class constructor. Initialize class members.
//
DigWrapper::DigWrapper(interwork::Argument *& iwArg, StringRef funcName, unsigned argNo, 
        Type *type, bool doMagic, 
        Context *ctx) : /*ModulePass(ID),*/ ctx(ctx), iwArg(iwArg), funcName(funcName), argNo(argNo),
        type(type), doMagic(doMagic) {

    info(v2) << "DigWrapper module started.\n";
}



// ------------------------------------------------------------------------------------------------
// Analysis starts from here. Simply pass the analyzed LLVM module, to Dig.
//
bool DigWrapper::runOnModule(const Module *M) {
    // NOTE: We cannot use the argument and the type from the other module
    //       (actual objects are different even they correspond to the same struct).
    Argument *arg = nullptr;
    Type *newTy   = nullptr;


    /* if type has no name is probably not a struct */
    if (Dig::getStructName(type) == "") {
        info(v2) << "Empty type string. Probably not a struct.\n";

        iwArg = nullptr;
        return false;
    }

    // --------------------------------------------------------------------- //
    //            * Search in the *new* module for the argument *            //
    // --------------------------------------------------------------------- //
    for(Module::const_reverse_iterator ii=M->rbegin(); ii!=M->rend(); ++ii) {
        Function &func = (Function &)*ii;
        
        if (func.getName() == funcName) {           // name match?
            unsigned k;

            /* find the appropriate argument */
            for (arg=func.arg_begin(), k=0; arg!=func.arg_end(); ++arg, ++k) {
                if (argNo == k) break;              // argument match?
            }

            break;
        }
    }

    /* if we can't find it, abort */
    if (arg == nullptr) {
        fatal() << "Cannot find argument in the new module\n";

        iwArg = nullptr;
        return false;
    }

    info(v1) << "Argument found: " << *arg << "\n";
    

    // --------------------------------------------------------------------- //
    //              * Search in the *new* module for the type *              //
    // --------------------------------------------------------------------- //
    TypeFinder structTypes;
    structTypes.run(*M, true);                      // find all (named) structs

    for (auto &structTy : structTypes) {            // iterate over structs
        // structTy->dump();

        if (structTy->getName() == Dig::getStructName(type)) {
            newTy = structTy;
            break;
        }
    }

    if (newTy == nullptr) {
        warning() << "Cannot find struct '" << Dig::getStructName(type) << "' in the new module\n";

        iwArg = nullptr;
        return false;
    }

    info(v1) << "Type found: " << *newTy << "\n";


    // --------------------------------------------------------------------- //
    //                       * Create a Dig object  *                        //
    // --------------------------------------------------------------------- //
    Dig *dig = new Dig(M, ctx);    

    /* now you can safely invoke digType() with the argument/type of the new module */
    iwArg = dig->digType(*arg, newTy, doMagic);


    if (iwArg) {                                    // make sure that this is not NULL
        /* don't forget to add the missing pointer indirections */
        iwArg->nptr[0] = Dig::getStructPtrs(type);
    }

    return false;                                   // nothing got changed
}

// ------------------------------------------------------------------------------------------------
