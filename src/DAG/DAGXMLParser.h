/*  Copyright 2012 Daniel Wilson.
 *
 *  DAGXMLParser.h
 *  Part of the gcat-core library.
 *
 *  The gcat-core library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  The gcat-core library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU Lesser General Public License for more details.
 *  
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with the gcat-core library. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef _DAG_XML_H_
#define _DAG_XML_H_
#include <iostream>
#include <sstream>
#include <vector>
#include <myutils.h>
#include <xercesc/sax2/SAX2XMLReader.hpp>
#include <xercesc/sax2/XMLReaderFactory.hpp>
#include <xercesc/sax2/DefaultHandler.hpp>
#include <xercesc/util/XMLString.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xercesc/sax2/Attributes.hpp>
#include <DAG/DAG.h>
#include <exception>

using namespace xercesc;
using namespace std;

namespace gcat {

class DAGXMLParserException : public exception {
protected:
	string msg;
public:
	DAGXMLParserException() throw();
	DAGXMLParserException(string msg_in) throw();
	virtual const char* what() const throw();
	~DAGXMLParserException() throw();
};

// Forward declaration (full declaration below)
class DAGXMLParser;

// The master parser handles events simply by passing them to the active parser
class DAGXMLMasterParser : public DefaultHandler {
private:
	DAG* _dag;
	DAGXMLParser* _active_parser;
public:
	// Constructor
	DAGXMLMasterParser(DAG* dag, DAGXMLParser* active_parser);
	// Destructor
	~DAGXMLMasterParser();
	// Functions that direct calls to the active parser
	void startElement(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs);
	void endElement(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname);
    void characters(const XMLCh* const chars, const XMLSize_t length);
	// The master parser handles parsing errors:
	void warning(const SAXParseException&);
	void error(const SAXParseException&);
	void fatalError(const SAXParseException&);
	// Get pointer to DAG
	DAG* getDAG();
	// Get pointer to active parser
	DAGXMLParser* get_active_parser();
	// Set active parser
	void set_active_parser(DAGXMLParser* active_parser);
	string elementName(const XMLCh* const localname);
};

// Abstract base class for active parsers (NB:- not derived from Xerces DefaultHandler)
class DAGXMLParser {
public:
	DAGXMLMasterParser* _master_parser;
	DAGXMLParser* _parent_parser;
	DAGXMLParser* _child_parser;
	/* Storage for name, type, attributes, etc? */
public:
	DAGXMLParser(DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
	virtual ~DAGXMLParser();
	// Pure virtual functions: default behaviours are specified in DAGXMLParserTemplate
	virtual void startElement(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs) = 0;
	virtual void endElement(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname) = 0;
	virtual void characters(const XMLCh* const chars, const XMLSize_t length) = 0;
	virtual void childElementReturns(DAGXMLParser* child_parser) = 0;
	// Convert named attributes to strings
	vector<string> attributesToStrings(const int nattr, const char* attrNames[], const Attributes& attrs);
	// Convert element name to string
	string elementName(const XMLCh* const localname);
	// Get DAG
	DAG* getDAG();
};

// Type definition for function pointer to DAGXMLParser factory
typedef DAGXMLParser* (*DAGXMLParserFactoryPtr)(const XMLCh* const, const XMLCh* const, const XMLCh* const, const Attributes&, DAGXMLMasterParser* const, DAGXMLParser* const);

// Base template for CRTP. Allows derived-class specific static functions and members, necessary for the DLL loading.
// Specialization by overloading, NOT virtual functions which are not allowed in templatized classes, and in any case
// CRTP offers an alternative, compile-time idiom for inheritance and polymorphism.
// NB: usually template definitions are in the header file (otherwise it gets complicated)
template <typename T>
class DAGXMLParserTemplate : public DAGXMLParser {
public:
	// Static map for relating XML names to C++ XML parser objects
	static map<string,DAGXMLParserFactoryPtr> startElementMap;
public:
	DAGXMLParserTemplate(DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParser(master_parser, parent_parser) {};
	DAGXMLParserTemplate(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParser(master_parser, parent_parser) {
		// When created from this constructor (called by the static factory function) pass control to beginParsing()
		// which can be specialized to give virtual function-like derived class-specific behaviour
		static_cast<T*>(this)->beginParsing(uri,localname,qname,attrs);
	};
	~DAGXMLParserTemplate() {};
	// Static functions
	static DAGXMLParser* factory(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) {
		return (DAGXMLParser*)(new T(uri,localname,qname,attrs,master_parser,parent_parser));
	}
	static DAGXMLParserFactoryPtr getfactory() {
		return &factory;
	}
	static void add_child(const string name, DAGXMLParserFactoryPtr facPtr) {
		map<string,DAGXMLParserFactoryPtr>::iterator it = startElementMap.find(name);
		if(it!=startElementMap.end()) {
			error("DAGXMLParserTemplate::add_child(): name already exists");
		}
		startElementMap.insert(pair<string,DAGXMLParserFactoryPtr>(name,facPtr));
		//cout << "DAGXMLParserTemplate<T>::add_child(): adding element " << name << " to object " << (int)&startElementMap << endl;
	}
	// Implement pure virtual functions from base class DAGXMLParser
	void startElement(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs) {
		static_cast<T*>(this)->implement_startElement(uri,localname,qname,attrs);
	}
	void endElement(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname) {
		static_cast<T*>(this)->implement_endElement(uri,localname,qname);
	}
	void characters(const XMLCh* const chars, const XMLSize_t length) {
		static_cast<T*>(this)->implement_characters(chars,length);
	}
	void childElementReturns(DAGXMLParser* child_parser) {
		static_cast<T*>(this)->implement_childElementReturns(child_parser);
	}
	// Virtual-like behaviour: overload these functions for derived class-specific behaviour
	// Default behaviour: do nothing
	void beginParsing(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs) {}
	// Default behaviour: cycle through startElementMap to find child parser to pass control to
	void implement_startElement(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs) {
		string element = elementName(localname);
		// Find element in startElementMap
		map<string,DAGXMLParserFactoryPtr>::iterator it = startElementMap.find(element);
		if(it!=startElementMap.end()) {
			// The DAGXMLParserFactoryPtr function creates a new DAGXMLParser which
			// takes control upon creation, and returns a pointer to the new object.
			DAGXMLParserFactoryPtr facPtr = it->second;
			_child_parser = (*facPtr)(uri,localname,qname,attrs,_master_parser,this);
		}
		else {
			// Default behaviour: This is probably a coding error assuming the XML document has already been validated using the XML Schema
			cout << "DAGXMLParser::startElement(): recognized elements are:\n";
			for(it=startElementMap.begin();it!=startElementMap.end();it++) {
				cout << it->first << endl;
			}
			string errMsg = "DAGXMLParser::startElement(): child element not expected: ";
			errMsg += elementName(localname);
			error(errMsg.c_str());
		}
	}	
	// Default behaviour: assumes the end element is correct because the XML document has already been validated using the XML Schema ** Could add checking for this **
	void implement_endElement(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname) {
		_master_parser->set_active_parser(_parent_parser);
		_parent_parser->childElementReturns(this);
	}
	// Default behaviour: return an error because no text is expected
	void implement_characters(const XMLCh* const chars, const XMLSize_t length) {
		error("DAGXMLParser::characters(): no text expected");
	}
	// Default behaviour: delete child parser to avoid memory leaks
	void implement_childElementReturns(DAGXMLParser* child_parser) {
		delete child_parser;
		_child_parser = 0;
	}
};
template <typename T> map<string,DAGXMLParserFactoryPtr> DAGXMLParserTemplate<T>::startElementMap;

template <class T>
bool from_string(T& t, string& s) {
	std::istringstream iss(s);
	return !(iss >> t).fail();
}

template <class T>
bool string_to_vector(vector<T>& t, string& s) {
	istringstream oss(s);
	t = vector<T>(0);
	T val_j;
	while(!(oss >> val_j).fail()) {
		t.push_back(val_j);
	}
	return oss.eof();
}

class topLevel_XMLParser : public DAGXMLParserTemplate<topLevel_XMLParser>  {
public:
	topLevel_XMLParser(DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
	topLevel_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
	~topLevel_XMLParser();
};

class gcatLibrary_XMLParser : public DAGXMLParser {
protected:
	int parsingLibraries;
public:
	gcatLibrary_XMLParser(DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
	gcatLibrary_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
	~gcatLibrary_XMLParser();
	// Inherited virtual functions
	void startElement(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs);
	void endElement(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname);
	void characters(const XMLCh* const chars, const XMLSize_t length);
	void childElementReturns(DAGXMLParser* child_parser);	
};
	
} // namespace gcat

#endif //_DAG_XML_H_
