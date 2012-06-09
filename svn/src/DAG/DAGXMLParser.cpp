/*  Copyright 2012 Daniel Wilson.
 *
 *  DAGXMLParser.cpp
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
#include <DAG/DAGXMLParser.h>

namespace gcat {

DAGXMLMasterParser::DAGXMLMasterParser(DAG* dag, DAGXMLParser* active_parser) : _dag(dag), _active_parser(active_parser) {
}

DAGXMLMasterParser::~DAGXMLMasterParser() {
}

void DAGXMLMasterParser::startElement(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs) {
	if(_active_parser==0) myutils::error("DAGXMLMasterParser::startElement(): _active_parser not set");
	//	cout << "DAGXMLMasterParser::startElement(): " << elementName(localname) << endl;
	_active_parser->startElement(uri,localname,qname,attrs);
}

void DAGXMLMasterParser::endElement(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname) {
	if(_active_parser==0) myutils::error("DAGXMLMasterParser::endElement(): _active_parser not set");
	_active_parser->endElement(uri,localname,qname);
}

void DAGXMLMasterParser::characters(const XMLCh* const chars, const XMLSize_t length) {
	if(_active_parser==0) myutils::error("DAGXMLMasterParser::characters(): _active_parser not set");
	_active_parser->characters(chars,length);
}

void DAGXMLMasterParser::warning(const SAXParseException& exception) {
	char* message = XMLString::transcode(exception.getMessage());
	stringstream wrnMsg;
	wrnMsg << "DAGXMLMasterParser: " << message << " at line: " << exception.getLineNumber();
	XMLString::release(&message);
	myutils::warning(wrnMsg.str().c_str());
}

void DAGXMLMasterParser::error(const SAXParseException& exception) {
	fatalError(exception);
}

void DAGXMLMasterParser::fatalError(const SAXParseException& exception) {
    char* message = XMLString::transcode(exception.getMessage());
	stringstream errMsg;
    errMsg << "DAGXMLMasterParser: " << message << " at line: " << exception.getLineNumber();
    XMLString::release(&message);
	DAGXMLParserException e = DAGXMLParserException(errMsg.str().c_str());
	throw e;
}

DAG* DAGXMLMasterParser::getDAG() {
	return _dag;
}

DAGXMLParser* DAGXMLMasterParser::get_active_parser() {
	return _active_parser;
}

void DAGXMLMasterParser::set_active_parser(DAGXMLParser* active_parser) {
	_active_parser = active_parser;
}

string DAGXMLMasterParser::elementName(const XMLCh* const localname) {
	char* message = XMLString::transcode(localname);
	string ret = message;
    XMLString::release(&message);
	return ret;
}

DAGXMLParser::DAGXMLParser(DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : _master_parser(master_parser), _parent_parser(parent_parser), _child_parser(0) {
	_master_parser->set_active_parser(this);
}

DAGXMLParser::~DAGXMLParser() {
}

vector<string> DAGXMLParser::attributesToStrings(const int nattr, const char* attrNames[], const Attributes& attrs) {
	vector<string> ret(nattr);
	XMLSize_t i;
	int j;
	for(i=0;i<attrs.getLength();i++) {
		char* lname = XMLString::transcode(attrs.getLocalName(i));
		char* val = XMLString::transcode(attrs.getValue(i));
		for(j=0;j<nattr;j++) {
			if(strcmp(lname,attrNames[j])==0) {
				ret[j] = val;
				break;
			}
		}
		if(j==nattr) {
			stringstream errMsg("DAGXMLParser::attributesToStrings(): Attribute not recognised: ");
			errMsg << lname;
			error(errMsg.str().c_str());
		}
		XMLString::release(&lname);
		XMLString::release(&val);
	}
	return ret;
}

string DAGXMLParser::elementName(const XMLCh* const localname) {
	char* message = XMLString::transcode(localname);
	string ret = message;
    XMLString::release(&message);
	return ret;
}

DAG* DAGXMLParser::getDAG() {
	return _master_parser->getDAG();
}

// Example of how to specialize this function
template<> void DAGXMLParserTemplate<topLevel_XMLParser>::beginParsing(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs) {
	cout << "template<> virtual void DAGXMLParserTemplate<topLevel_XMLParser>::beginParsing(): Just checking it works!\n";
}

DAGXMLParserException::DAGXMLParserException() throw() : exception(), msg("") {}

DAGXMLParserException::DAGXMLParserException(string msg_in) throw() : exception(), msg(msg_in) {}

const char* DAGXMLParserException::what() const throw() {
	return msg.c_str();
}

DAGXMLParserException::~DAGXMLParserException() throw() {}

topLevel_XMLParser::topLevel_XMLParser(DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<topLevel_XMLParser>(master_parser,parent_parser) {
	// No attributes are taken
}

topLevel_XMLParser::topLevel_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<topLevel_XMLParser>(master_parser,parent_parser) {
	// No attributes are taken
}

topLevel_XMLParser::~topLevel_XMLParser() {
}

gcatLibrary_XMLParser::gcatLibrary_XMLParser(DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParser(master_parser,parent_parser), parsingLibraries(0) {
	// No attributes are taken
}

gcatLibrary_XMLParser::gcatLibrary_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParser(master_parser,parent_parser), parsingLibraries(0) {
	// No attributes are taken
}

gcatLibrary_XMLParser::~gcatLibrary_XMLParser() {
}

void gcatLibrary_XMLParser::startElement(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs) {
	string element = elementName(localname);
	// Recognised elements
	if(element=="libraries") {
		++parsingLibraries;
	}
	else if(element=="library") {
		// Only process library elements if they occur within the first block of <libraries>...</libraries>
		if(parsingLibraries==1) {
			// Read in the file name
			const int nattr = 1;
			const char* attrNames[nattr] = {"file"};
			vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
			// Load the library, and add to the list of chameleon schemas. NB:- library must ensure it is not loaded multiple times
			getDAG()->add_chameleon(load_library(sattr[0].c_str()));
		}
	}
	else {
		// Ignore
	}
}

void gcatLibrary_XMLParser::characters(const XMLCh* const chars, const XMLSize_t length) {
	// Do nothing
}

void gcatLibrary_XMLParser::childElementReturns(DAGXMLParser* child_parser) {
	delete child_parser;
	_child_parser = 0;
	// Distributions take care of themselves, so no need to act
}

void gcatLibrary_XMLParser::endElement(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname) {
	string element = elementName(localname);
	if(element=="libraries") {
		++parsingLibraries;
	}
	else {
		// Ignore
	}
}
	
} // namespace gcat
