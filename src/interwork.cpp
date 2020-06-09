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
 * interwork.cpp
 *
 * This file contains the actual functions, as declared in interwork.h.
 *
 * NOTE: I migrated functions to the .cpp file because of the forward declaration of FunctionPtr.
 *       (I can't use funcptr->deepCopy() inside Argument::deepCopy()). However, I kept Attributes
 *       declarations to .h file as they are templated.
 *
 */
// ------------------------------------------------------------------------------------------------
#include "interwork.h"

using namespace interwork;
using namespace std;



// ------------------------------------------------------------------------------------------------

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * *                                                                                           * *
 * *                                      ARGUMENT CLASS                                       * *
 * *                                                                                           * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// ------------------------------------------------------------------------------------------------
// Return the total number of pointers.
//
uint8_t Argument::nptrs() {
    return nptr[0] + nptr[1];
}



// ------------------------------------------------------------------------------------------------
// Check if an argument is of basic type.
//
bool Argument::isBasic() {
    return isBaseTy;
}



// ------------------------------------------------------------------------------------------------
// Get the size of the basic type (in bytes).
// 
size_t Argument::basicSz() {    
    switch (baseType) {
      case Ty_void:    return 0;
      case Ty_i8:      return 1;
      case Ty_i16:     return 2;
      case Ty_i32:     return 4;
      case Ty_i64:     return 8;
      case Ty_float:   return 4;
      case Ty_double:  return 8;
      case Ty_struct:  return 0;
    }

    throw FuzzGenException("basicSz(): Invalid basic type to get sizeof");
}



// ------------------------------------------------------------------------------------------------
// Check if the stripped (without the pointers) argument is of basic type.
//
bool Argument::isBasicStripped() {
    return baseType == Ty_null  ||
           baseType == Ty_i8    ||
           baseType == Ty_i16   ||
           baseType == Ty_i32   ||
           baseType == Ty_i64   ||
           baseType == Ty_float ||
           baseType == Ty_double;
}



// ------------------------------------------------------------------------------------------------
// Check whether 2 arguments have the exact same type.
//
bool Argument::compare(string arg, bool ignorePtr) {
    if (!ignorePtr) {
        return this->tyStr == arg;
    } else {
        /* do a manual strcmp() but this time ignore pointers */
        string s1, s2;


        for(char &ch : this->tyStr) {
            if (ch != '*') s1 += ch;                // strcpy and ignore '*'
        }

        for(char &ch : arg) {
            if (ch != '*') s2 += ch;                // strcpy and ignore '*'
        }

        return s1 == s2;                            // now compare
    }
}



// ------------------------------------------------------------------------------------------------
// Collect all dependencies that are defined.
//
void Argument::getDefDeps(set<unsigned> &deps) {

    /* if a dependency is defined, get it */
    if (depTy & Dep_def) {
        deps.insert(depID);
    }

    /* recursively collect dependencies from each subelement */
    for (auto ii=subElements.begin(); ii!=subElements.end(); ++ii) {
        (*ii)->getDefDeps(deps);
    }

    /* and each switch argument */
    for (auto ii=switchArgs.begin(); ii!=switchArgs.end(); ++ii) {
        (*ii)->getDefDeps(deps);
    }
}



// ------------------------------------------------------------------------------------------------
// Kill a dependence (remove it from all elements).
//
void Argument::killDep(unsigned killID) {

    /* if a dependency is used, kill it */
    if ((depTy & Dep_use) && depID == killID) {
        depID = 0xffff;                             // clear dependence
        depTy &= ~Dep_use;                          // drop usage
    }

    if ((depTy & Dep_init) && depID == killID) {
        depIDInit = 0xffff;                         // clear dependence
        depTy &= ~Dep_init;                         // drop usage
    }


    /* recursively kill dependencies from each argument */
    for (auto ii=subElements.begin(); ii!=subElements.end(); ++ii) {   
        (*ii)->killDep(killID);
    }
}



// ------------------------------------------------------------------------------------------------
// Return a deep copy of the object.
//
Argument *Argument::deepCopy() {
    Argument *copy = new Argument();

    copy->tyStr      = tyStr;                       // copy base elements one by one
    copy->baseType   = baseType;
    copy->isBaseTy   = isBaseTy;
    copy->isSigned   = isSigned;
    copy->isConst    = isConst;
    copy->size       = size;
    copy->nptr[0]    = nptr[0];
    copy->nptr[1]    = nptr[1];
    copy->nptrIdx    = nptrIdx;
    copy->nsz        = nsz;
    copy->structName = structName;
    copy->fieldName  = fieldName;
    copy->off        = off;
    copy->idx        = idx;
    copy->name       = name;
    copy->parent     = parent;
    copy->depID      = depID; 
    copy->depIDInit  = depIDInit;
    copy->depTy      = depTy;
    copy->prefix     = prefix;
    copy->setByExt   = setByExt;
    copy->hasFakeDep = hasFakeDep;
    copy->funcptr    = funcptr ? funcptr->deepCopy() : nullptr;
    copy->attr       = attr    ? attr->deepCopy()    : nullptr;

    copy->sz.assign(sz.begin(), sz.end());

    /* recursively copy each subelement */
    for (auto ii=subElements.begin(); ii!=subElements.end(); ++ii) {
        copy->subElements.push_back( (*ii)->deepCopy() );
    }


    /* recursively copy switch arguments */
    for (auto ii=switchArgs.begin(); ii!=switchArgs.end(); ++ii) {
        copy->switchArgs.push_back( (*ii)->deepCopy() );
    }


    return copy;
}



// ------------------------------------------------------------------------------------------------
// Replace all contents of an Argument with another.
//
void Argument::replace(Argument *arg) {
    this->tyStr      = arg->tyStr;
    this->baseType   = arg->baseType;
    this->isBaseTy   = arg->isBaseTy;
    this->isSigned   = arg->isSigned;
    this->isConst    = arg->isConst;
    this->size       = arg->size;
    this->nptr[0]    = arg->nptr[0];
    this->nptr[1]    = arg->nptr[1];
    this->nptrIdx    = arg->nptrIdx;
    this->nsz        = arg->nsz;
    this->structName = arg->structName;
    this->fieldName  = arg->fieldName;
    this->off        = arg->off;
    this->idx        = arg->idx;
    this->name       = arg->name;
    this->parent     = arg->parent;
    this->depID      = arg->depID; 
    this->depIDInit  = arg->depIDInit;
    this->depTy      = arg->depTy;
    this->prefix     = arg->prefix;
    this->setByExt   = arg->setByExt;
    this->hasFakeDep = arg->hasFakeDep;
    this->funcptr    = arg->funcptr ? arg->funcptr->deepCopy() : nullptr;
    this->attr       = arg->attr    ? arg->attr->deepCopy()    : nullptr;

    this->sz.assign(arg->sz.begin(), arg->sz.end());


    // TODO: release memory for subElements first
    this->subElements.clear();                      // clear any leftovers

    
    /* recursively copy each subelement (no need to replace) */
    for (auto ii=arg->subElements.begin(); ii!=arg->subElements.end(); ++ii) {
        this->subElements.push_back( (*ii)->deepCopy() );
    }


    /* recursively copy switch arguments */
    for (auto ii=arg->switchArgs.begin(); ii!=arg->switchArgs.end(); ++ii) {
        this->switchArgs.push_back( (*ii)->deepCopy() );
    }
}



// ------------------------------------------------------------------------------------------------
// Print all fields of the object (very useful for debugging).
//
string Argument::dump() {
    ostringstream oss;

    oss << "Type=" << tyStr << "; ";
    oss << "idx=" << (int)idx << "; ";
    oss << "name=" << name << "; ";
    oss << "TyID=";

    switch (baseType) {
      case Ty_void:    oss << "void";   break;
      case Ty_null:    oss << "NULL";   break;
      case Ty_i8:      oss << "i8";     break;
      case Ty_i16:     oss << "i16";    break;
      case Ty_i32:     oss << "i32";    break;
      case Ty_i64:     oss << "i64";    break;
      case Ty_float:   oss << "float";  break;
      case Ty_double:  oss << "double"; break;
      case Ty_struct:  oss << "struct"; break;
      case Ty_funcptr: oss << "funptr";
    }

    oss << "; ";
    oss << "size=" << size << "; ";
    oss << "isBasic=" << isBasic() << "; ";
    oss << "isSigned=" << isSigned << "; ";
    oss << "isConst=" << isConst   << "; ";
    oss << "nptr=" << (int)nptr[0] << "," << (int)nptr[1] << "; ";
    oss << "nsz=" << nsz;

    /* print sizes of each dimension */
    if (nsz > 1) {
        oss << " (";
        for (auto i : sz) oss << i << ", ";
        oss << ")";
    }

    oss << "; ";

    oss << "struct=" << structName << "; " << "field=" << fieldName << "; ";
    oss << "off=" << off << "; ";

    if (!attr) {
        oss << "attr=NULL; ";
    } else  {
        oss << "attr=0x" << hex << setfill('0') << setw(4) << attr->flags << dec
            << "; predefined=" << attr->dump("V")
            << "; reference=" << attr->getRef() << "; ";
    }

    oss << "subelts=#"    << subElements.size()   << "; "       
        << "funcptr="     << (funcptr != nullptr) << "; "
        << "parent="      << (parent != nullptr)  << "; "
        << "depTy="       << depTy << "; depID=0x"  << hex << depID << dec << "; "
        << "depIDInit=0x" << hex << depIDInit << dec << "; "
        << "prefix="      << (char)prefix << "; "
        << "setByExt="    << setByExt << "; "
        << "hasFakeDep="  << hasFakeDep << "; ";


    oss << "addr=0x" << hex << setfill('0') << setw(12) << (uint64_t)this << dec << ";";
        
    return oss.str();
}



// ------------------------------------------------------------------------------------------------
// Generate a unique hash based on the object. Note that not all fields should participate on the
// hash.
//
string Argument::hash(int hash_type) {
    ostringstream oss;


    oss << tyStr << "|" << (int)idx << "|" << name << "|" << baseType << "|" << size  << "|"
        << (int)nptr[0] << "," << (int)nptr[1] << "|" << (int)nptrIdx << "|" << nsz << "|";

    if (nsz > 1) {
        for (auto i : sz) oss << i << ",";
    }

    oss << "|" << structName << "|" << fieldName << "|" << off
        << "|" << subElements.size()
        << "|" << (funcptr != nullptr ? funcptr->hash() : "NULL")
        << "|" << (char)prefix;


    /* recursively get the hash of each subelement */
    for (auto ii=subElements.begin(); ii!=subElements.end(); ++ii) {
        oss << "$" << (*ii)->hash(hash_type);
    }


    /* add the remaining fields if a strong hash is requsted */
    if (hash_type == HASHTYPE_STRONG) {
        if (!attr) {
            oss << "|NULL";
        } else  {
            oss << "|" << attr->flags << "|" << attr->dump("") << "|" << attr->getRef() << "|";
        }

        oss << "|" << depTy << "|" << depID << "|" << depIDInit
            << "|" << setByExt << "|" << hasFakeDep;

        // TODO: Add parent and switchArgs?
    }

    return oss.str();
}



// ------------------------------------------------------------------------------------------------

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * *                                                                                           * *
 * *                                  FUNCTION POINTER CLASS                                   * *
 * *                                                                                           * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// ------------------------------------------------------------------------------------------------
// Return a deep copy of the object.
//
FunctionPtr* FunctionPtr::deepCopy() {
    FunctionPtr *copy = new FunctionPtr();

    copy->funame     = funame;
    copy->callee     = callee;
    copy->retval     = retval ? retval->deepCopy() : nullptr;
    copy->retValUsed = retValUsed;

    copy->paramMap.assign(paramMap.begin(), paramMap.end());
    
    /* recursively copy each subelement */
    for (auto ii=params.begin(); ii!=params.end(); ++ii) {
        copy->params.push_back( (*ii)->deepCopy() );
    }

    return copy;
}



// ------------------------------------------------------------------------------------------------
// Print all fields of the object (very useful for debugging).
//
string FunctionPtr::dump() {
    ostringstream oss;

    oss << "Return Value: " << (retval ? retval->dump() : nullptr) << "\n";

    for (auto ii=params.begin(); ii!=params.end(); ++ii) {
        oss << "Param: " << (*ii)->dump() << "\n";
    }

    return oss.str();
}



// ------------------------------------------------------------------------------------------------
// Generate a unique hash based on the object. Note that not all fields should participate on the
// hash.
string FunctionPtr::hash() {
    ostringstream oss;


    oss << callee << "|" << (retval ? retval->hash() : nullptr) << "|";

    for (auto ii=params.begin(); ii!=params.end(); ++ii) {
        oss << "$" << (*ii)->hash();
    }

    return oss.str();
}



// ------------------------------------------------------------------------------------------------

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * *                                                                                           * *
 * *                                      API CALL CLASS                                       * *
 * *                                                                                           * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// ------------------------------------------------------------------------------------------------
// Collect all dependencies that are defined.
//
void APICall::getDefDeps(set<unsigned> &deps) {

    /* if a dependency is defined (from return value), get it */
    if (depTy & Dep_def) {
        deps.insert(depID);
    }

    /* recursively collect dependencies from each argument */
    for (auto ii=args.begin(); ii!=args.end(); ++ii) {
        (*ii)->getDefDeps(deps);
    }
}


// ------------------------------------------------------------------------------------------------
// Kill a dependence (remove it from all arguments).
//
void APICall::killDep(unsigned killID) {

    /* if a dependency is used, kill it */
    if ((depTy & Dep_use) && depID == killID) {
        depID = 0xffff;                             // clear dependence
        depTy &= ~Dep_use;                          // drop usage
    }

    // return values have no Dep_init


    /* recursively kill dependencies from each argument */
    for (auto ii=args.begin(); ii!=args.end(); ++ii) {   
        (*ii)->killDep(killID);
    }
}


// ------------------------------------------------------------------------------------------------
// Return a deep copy of the object.
//
APICall *APICall::deepCopy() {
    APICall *copy = new APICall();

    copy->name  = name;
    copy->nargs = nargs;

    copy->vals.assign(vals.begin(), vals.end());
    copy->ops.assign(ops.begin(), ops.end());

    copy->retVal = retVal ? retVal->deepCopy() : nullptr;
    
    /* recursively copy each argument */
    for (auto ii=args.begin(); ii!=args.end(); ++ii) {
        copy->args.push_back( (*ii)->deepCopy() );
    }

    copy->depTy  = depTy;
    copy->depID  = depID;
    copy->depAsg = depAsg;    

    copy->isVariadic = isVariadic;
    copy->retvalSeq  = retvalSeq;

    copy->vertex = vertex;
    
    return copy;
}



// ------------------------------------------------------------------------------------------------
// Generate a unique hash based on the object. Note that not all fields should participate on the
// hash.
//
string APICall::hash(int hash_type) {
    ostringstream oss;


    oss << "|" << name << "|" << nargs << "|" << isVariadic << "|" << retvalSeq << "|";

    /* get the hash of each argument */
    for (auto ii=args.begin(); ii!=args.end(); ++ii) {
        oss << "$" << (*ii)->hash();
    }

    oss << "|";


    /* add the remaining fields if a strong hash is requsted */
    if (hash_type == HASHTYPE_STRONG) {

        for (auto ii=vals.begin(); ii!=vals.end(); oss << *(ii++) << "|");
        for (auto ii=ops.begin();  ii!=ops.end();  oss << *(ii++) << "|");
        
        oss << depTy << "|" << depID << "|";
    }


    return oss.str();
}

// ------------------------------------------------------------------------------------------------
