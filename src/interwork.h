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
 * interwork.h
 *
 * TODO: Write a small description.
 *
 */
// ------------------------------------------------------------------------------------------------
#ifndef LIBRARY_INTERWORK_H
#define LIBRARY_INTERWORK_H

#include "common.h"

#include <iostream>                                 // c++ includes
#include <iomanip>
#include <sstream>
#include <cstdint>
#include <type_traits>
#include <fstream>
#include <string>
#include <vector>
#include <list>
#include <map>
#include <set>


using namespace std;



// ------------------------------------------------------------------------------------------------
// This namespace contains the interface that analyzer uses to communicate with the composer.
// The class hierarchy of interwork is show below:
//
//      +-----------------------------+
//      |           APICall           |<--------------------------------------------+
//      +--------------+--------------+                                             |
//                     |                                                            |
//                     +-----------------+                                          |
//                                       |                                          |
//             +-------------------------+------------+------------------+          |
//             |                         |            |                  |          |
//             |                         |            |                  |          |
//      +------v------+             +----v-----+ +----v-----+       +----v-----+    |
//      | ReturnValue |             | Argument +-+ Argument +- ... -+ Argument +----+
//      +------+------+             +----+-----+ +----+-----+       +----+-----+
//             |                         |            |                  |
//             |                         |            |                  |
//             +-------------------------+------------+------------------+
//                                       |
//                                       |
//      +------------+              +----v-----+
//      | Attributes +------------->| BaseAttr |
//      +------------+              +----------+
//
namespace interwork {

/* basic C++ types (list is not complete) */
enum BaseTypes {
    Ty_invalid = 0xffffffff,
    Ty_void    = 0,
    Ty_null,                                        // NULL pointer
    Ty_i8,                                          // integers
    Ty_i16,
    Ty_i32,
    Ty_i64,
    Ty_float,                                       // floating point
    Ty_double,
    Ty_struct,                                      // structures (composite type)
    Ty_funcptr                                      // function pointer
};


/* Dependency types */
enum DependencyTypes {
    Dep_none = 0x00,                                // no dependency
    Dep_def  = 0x01,                                // define a dependency
    Dep_use  = 0x02,                                // use a dependency
    Dep_init = 0x04                                 // initialize from a dependency
};


/* Argument prefixes (for weird pointer castings) */
enum ArgumentPrefix {
    Pref_none  = ' ',                               // no prefix
    Pref_deref = '*',                               // dereference prefix "*")
    Pref_amp   = '&'                                // ampersand prefix "&"
};

/* Hash types for arguments */
enum HashType {
    HASHTYPE_WEAK = 0,                         // weak hash (for coalescing)
    HASHTYPE_STRONG                            // strong hash (for removing duplicates)
};


/* Dump mode for BaseAttr->dump() */
enum BaseAttrDumpMode {
    BASEATTR_MODE_DECL = 0,                         // C array declaration
    BASEATTR_MODE_VALUES                            // comma separated values only
};


class Argument;                                     // forward declaration

// ------------------------------------------------------------------------------------------------
// Function attributes may contain predefined values. These values have the same type with the
// argument, so the class that is used to hold attributes must be templated. However, Argument
// class contains an attribute object, which means that Argument class must be templated as well.
// But this is an issue, because at the time that Argument instances are created, the actual type
// of the argument is not known (type is revealed after analysis).
//
// To overcome this issue, we use polymorphism: We define a base class "BaseAttr", which is not
// templated, so Argument class can use it, and a templated derived class "Attributes", which
// inherits from BaseAttr. We use Attributes class to store all predefined values and we
// downcast it to BaseAttr before we store in Argument. A virtual function is also used to
// retrieve the predefined values.
//
// Predefined values are only needed by the composer, so instead of returning the actual values
// (remember that we don't their type), we simply pack them into a string, which is a valid
// c++ array declaration, and we return this string.
//

/* Base class for argument attributes */
class BaseAttr {
public:
    int      flags;                                 // argument attributes (set as flags)
    // Argument *dependency;                        // DEPRECATED
    set<string> predefinedVals;                     // predefined values from previous merges


    /* class constructor */
    BaseAttr(int flags) : flags(flags) { }

    /* convert predefined values set into a nice string s*/
    string toString(set<string> predefinedVals) {
        string values = "";

        for (auto ii=predefinedVals.begin(); ii!=predefinedVals.end(); ++ii) {
            values += (*ii) + ", ";
        }

        if (values.length() > 2) {
            values.pop_back();                      // drop last comma
            values.pop_back();
        }

        return values;
    }

    /* other functions */
    virtual BaseAttr *deepCopy()      { return nullptr; } // these are never invoked
    virtual string    dump(string="", int=BASEATTR_MODE_DECL) { return ""; }
    virtual bool      isZeroAttr()    { return false; }   //
    virtual size_t    getSize()       { return 0;  }      //
    virtual string    getRef()        { return ""; }      //
    virtual void      addAttr(int)    { }                 //
    virtual void      addRef(string)  { }                 //


    /* virtual destructor is also needed */
    virtual ~BaseAttr() { }
};



/* Base class for argument attributes */
// TODO: Which is this templated? predefined values could be represented just as a string...
template <typename T>
class Attributes : public BaseAttr {
public:

    /* class constructor */
    Attributes(int flags, string type) : BaseAttr(flags), type(type) { }


    /* push a value to the predefined set */
    void push(T v) { predefined.insert(v); }


    /* get predefined set size*/
    size_t getSize() override { return predefinedVals.size() + predefined.size(); }


    /* get reference attribute */
    string getRef() override { return reference; } 


    /* add a new attribute */
    void addAttr(int a) override { flags |= a; }


    /* add a reference attribute */
    void addRef(string refname) override { reference = refname; }


    /* return a deep copy of the object */
    BaseAttr *deepCopy() override {
        Attributes<T> *copy = new Attributes<T>(flags, type);
        
        copy->reference = reference;

        /* copy predefined values */
//        for (auto ii=predefinedVals.begin(); ii!=predefinedVals.end(); ++ii) {
//            copy->predefinedVals.insert(*ii);
//        }
        
        /* copy predefined attributes one by one */
        for (typename std::set<T>::iterator ii=predefined.begin(); ii!=predefined.end(); ++ii) { 
            copy->predefined.insert(*ii);
        }

        return copy;                                // upcast
    }


    /* convert the predefined values to a C++ constant array declaration */
    string dump(string varnam="", int mode=BASEATTR_MODE_DECL) override {
        string decl("const " + type + " " + varnam + "[] = {");


        if (mode == BASEATTR_MODE_VALUES) {         // check mode
            decl = "";                              // clear declaration
        }


        /* base check to make sure that attributes are not malformed */
        if (predefined.size() > 0 && reference != "") {                
            throw FuzzGenException("Attributes<T>: Cannot have a reference with a predefined set");
        }


        if (predefined.size() < 1) {                // bounds check
            return  toString(predefinedVals);

        } else if (predefined.size() == 1 && predefinedVals.size() < 1) {

            /* there's 1 element only (special case) */
            for (typename std::set<T>::iterator ii=predefined.begin(); ii!=predefined.end();
                    ++ii) {

                return to_string(*ii++);
            }
        }

        /* typeid(T).name() is the best option, but it needs RTTI which LLVM unhappy */

        /* pack all predefined values */
        for (typename std::set<T>::iterator ii=predefined.begin(); ii!=predefined.end();
                decl+=to_string(*ii++) + ", ")
            { }

        decl.pop_back();                            // drop the last comma
        decl.pop_back();


        if (predefinedVals.size() > 0) {            // add other predefined values (if exist)
            decl += ", " + toString(predefinedVals);
        }


        /* return declaration */        
        return decl + (mode == BASEATTR_MODE_DECL ? "};" : "");
    }


    /* check if there's only 1 attribute and it's 0 */
    bool isZeroAttr() override {
        if (predefined.size() != 1) {
            return false;
        }

        /* there's 1 element only. Check if it's 0 */
        for (typename std::set<T>::iterator ii=predefined.begin(); ii!=predefined.end(); ++ii) {
            return !(*ii++);
        }

        return false;
    }


private:
    string type;                                    // type name "int", "float", etc.
    set<T> predefined;                              // predefined set (may be empty)
    string reference;                               // reference variable (if exists)
};



// ------------------------------------------------------------------------------------------------
// Forward declaration for function pointers (see below).
//
class FunctionPtr;



// ------------------------------------------------------------------------------------------------
// Actual class to hold argument's information (everything that the composer needs to know).
//
class Argument {
public:
    string   tyStr = "$NOTYPE$";                    // LLVM type as a string (for quick comparisons)

    int      baseType = Ty_invalid;                 // base type (from BaseTypes)
    bool     isBaseTy = 0;                          // flag indicating the base types
    bool     isSigned = 0;                          // flag indicated if base type is signed
    bool     isConst  = 0;                          // flag indicated if base type is const
    uint64_t size     = 0;                          // type size

    uint8_t  nptr[2] = {0, 0};                      // levels of pointer indirections
    uint8_t  nptrIdx = 0;                           // index for nptr

    size_t   nsz = 0;                               // size (arrays: >1, others: =1)
    vector<size_t> sz;                              // size of each dimension

    string   structName = "";                       // structs also need a name
    string   fieldName  = "";                       // name for struct elements
    uint64_t off        = 0;                        // and an element offset

    uint8_t  idx   = 0;                             // element index in struct
    string   name  = "";                            // argument name
    BaseAttr *attr = nullptr;                       // argument attributes

    list<Argument *> subElements;                   // subelements (for nested structs)
    Argument *parent = nullptr;                     // the parent of a subelement (if exists)

    FunctionPtr *funcptr = nullptr;                 // when argument is a function pointer

    unsigned depID     = 0x0000ffff,                // dependence IDs and type
             depIDInit = 0x0000ffff;                // 16MSB = dID, 16LSB = struct offset
    int      depTy     = Dep_none;

    int prefix = Pref_none;                         // argument prefix (*, &, or none)

    bool setByExt = false;                          // true if object processed by external module

    bool hasFakeDep = false;                        // true if object has a fake dependency

    vector<Argument*> switchArgs;                   // "switch" arguments (for coalesced nodes) 


    /* total number of pointers */
    uint8_t nptrs();

    /* check if an argument is of basic type */
    bool isBasic();

    /* get the size of the basic type */
    size_t basicSz();

    /* check if the stripped (i.e., without pointers) argument is of basic type */
    bool isBasicStripped();

    /* check whether 2 arguments have the exact same type */
    bool compare(string, bool=false);

    /* collect all dependencies that are defined */
    void getDefDeps(set<unsigned> &);

    /* kill a dependence from all arguments */
    void killDep(unsigned);

    /* return a deep copy of the object */
    Argument *deepCopy();

    /* replace all contents of an Argument with another  */
    void replace(Argument *);

    /* print all fields of the object (very useful for debugging) */
    string dump();

    /* generate a unique hash based on the object */
    string hash(int=HASHTYPE_WEAK);

};


using Element     = Argument;                       // a struct element is also an argument
using ReturnValue = Argument;                       // a return value is also an argument



// ------------------------------------------------------------------------------------------------
// Function pointers
//
class FunctionPtr {
public:   
    string           funame;                        // function name (we may give it later on)
    bool             hasDecl = false;               // when true, there is a function declaration
    list<Argument *> params;                        // parameters
    Argument         *retval = nullptr;             // return value

    string           callee;                        // callee function
    vector<unsigned> paramMap;                      // mapping between callee and wrapper parameters
    bool             retValUsed = false;            // when true, calee's return value is returned


    /* return a deep copy of the object */    
    FunctionPtr *deepCopy();

    /* print return value and parameters of the function */
    string dump();

    /* generate a unique hash based on the object */
    string hash();
};



// ------------------------------------------------------------------------------------------------
// The actual object that is being sent to the composer
//
class APICall {
public:
    /* no need for get()/set() functions. Keep it simple ;) */

    string name = "$UNUSED$";                       // function name

    vector<uint64_t>  vals;                         // return values that indicate a failure
    vector<string>    ops;                          // operators for these values

    size_t            nargs = 0;                    // number of arguments
    vector<Argument*> args;                         // argument list
    Argument          *retVal = nullptr;            // the type of the return value

    /* return value element sequence when it is stored in an struct element */
    string retvalSeq = "";

    bool isVariadic = false;                        // true if function is variadic


    /* TODO: Deprecate these. Instead use retVal->depTy and etVal->depID */
    int      depTy     = Dep_none;                  // dependence type
    unsigned depID     = 0x0000ffff;                // and ID

    vector<unsigned> depAsg;                        // dependence assignments


    unsigned vertex;                                // vertex ID in AADG (DEBUG ONLY)



    /* collect all dependencies that are defined */
    void getDefDeps(set<unsigned> &);

    /* kill a dependence from all arguments */
    void killDep(unsigned);

    /* return a deep copy of the object */    
    APICall *deepCopy();

    /* generate a unique hash based on the object */
    string hash(int=HASHTYPE_WEAK);
};

}

// ------------------------------------------------------------------------------------------------
#endif
