/*  Copyright 2012 Daniel Wilson.
 *
 *  DAGreadXML.cpp
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
#include <DAG/DAG.h>
#include <DAG/DAGXMLParser.h>
#include <dlfcn.h>
#include <gcat/gcat.core1.0.xsd.h>
#include <gcat/gcat.skeleton1.0.xsd.h>
#include <RandomVariables/RandomVariablesXML.h>
#include <Transformations/TransformationsXML.h>
#include <Distributions/DistributionsXML.h>
#include <Inference/InferenceXML.h>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <errno.h>
#include <unistd.h>

namespace gcat {

void DAG::readXML(const char* xmlFile, const char* xsdfile) {
	// Initialize my parser(s)
	DAGXMLMasterParser masterParser(this,0);
	DAGXMLParser* topParser = new topLevel_XMLParser(&masterParser,0);
	masterParser.set_active_parser(topParser);
	
	try {
		XMLPlatformUtils::Initialize();
	}
	catch (const XMLException& toCatch) {
		char* message = XMLString::transcode(toCatch.getMessage());
		string errMsg = "readXML(): ";
		errMsg += message;
		XMLString::release(&message);
		error(errMsg.c_str());
	}
	
	XMLCh* xsdFile = XMLString::transcode(xsdfile);
	SAX2XMLReader* parser = XMLReaderFactory::createXMLReader();
	parser->setFeature(XMLUni::fgSAX2CoreValidation, true);
	parser->setFeature(XMLUni::fgSAX2CoreNameSpaces, true);	  // enables namespace use (default anyway)
	parser->setFeature(XMLUni::fgXercesSchema, true);         // enables schema processing (default anyway)
	parser->setProperty(XMLUni::fgXercesSchemaExternalSchemaLocation,xsdFile);
	//setExternalNoNamespaceSchemaLocation
	DefaultHandler* defaultHandler = (DefaultHandler*)&masterParser;
	parser->setContentHandler(defaultHandler);
	parser->setErrorHandler(defaultHandler);
	
	try {
		parser->parse(xmlFile);
	}
	catch (...) {
		//error("readXML(): unexpected exception");
		delete parser;
		throw;
	}
	
	delete parser;
}

void DAG::readXML(const char* xmlFile) {
	// Initialize my parser(s)
	DAGXMLMasterParser masterParser(this,0);
	DAGXMLParser* topParser = new topLevel_XMLParser(&masterParser,0);
	masterParser.set_active_parser(topParser);
	
	try {
		XMLPlatformUtils::Initialize();
	}
	catch (const XMLException& toCatch) {
		char* message = XMLString::transcode(toCatch.getMessage());
		string errMsg = "readXML(): ";
		errMsg += message;
		XMLString::release(&message);
		error(errMsg.c_str());
	}
	
	//XMLCh* xsdFile = XMLString::transcode(xsdfile);
	SAX2XMLReader* parser = XMLReaderFactory::createXMLReader();
	parser->setFeature(XMLUni::fgSAX2CoreValidation, true);
	parser->setFeature(XMLUni::fgSAX2CoreNameSpaces, true);	  // enables namespace use (default anyway)
	parser->setFeature(XMLUni::fgXercesSchema, true);         // enables schema processing (default anyway)
	//	parser->setFeature(XMLUni::fgXercesHandleMultipleImports, true);	// allow multiple imports of the same namespace (override default)
	//parser->setProperty(XMLUni::fgXercesSchemaExternalSchemaLocation,xsdFile);
	//setExternalNoNamespaceSchemaLocation
	DefaultHandler* defaultHandler = (DefaultHandler*)&masterParser;
	parser->setContentHandler(defaultHandler);
	parser->setErrorHandler(defaultHandler);
	
	try {
		parser->parse(xmlFile);
	}
	catch (...) {
		//error("readXML(): unexpected exception");
		delete parser;
		throw;
	}
	
	delete parser;
}

void DAG::readXML_firstpass(const char* xmlFile, const char* xsdfile) {
	// Initialize my parser(s)
	DAGXMLMasterParser masterParser(this,0);
	DAGXMLParser* topParser = new gcatLibrary_XMLParser(&masterParser,0);
	masterParser.set_active_parser(topParser);
	
	try {
		XMLPlatformUtils::Initialize();
	}
	catch (const XMLException& toCatch) {
		char* message = XMLString::transcode(toCatch.getMessage());
		string errMsg = "readXML(): ";
		errMsg += message;
		XMLString::release(&message);
		error(errMsg.c_str());
	}
	
	XMLCh* xsdFile = XMLString::transcode(xsdfile);
	SAX2XMLReader* parser = XMLReaderFactory::createXMLReader();
	parser->setFeature(XMLUni::fgSAX2CoreValidation, true);
	parser->setFeature(XMLUni::fgSAX2CoreNameSpaces, true);	  // enables namespace use (default anyway)
	parser->setFeature(XMLUni::fgXercesSchema, true);         // enables schema processing (default anyway)
	parser->setProperty(XMLUni::fgXercesSchemaExternalSchemaLocation,xsdFile);
	//setExternalNoNamespaceSchemaLocation
	DefaultHandler* defaultHandler = (DefaultHandler*)&masterParser;
	parser->setContentHandler(defaultHandler);
	parser->setErrorHandler(defaultHandler);
	
	try {
		parser->parse(xmlFile);
	}
	catch (...) {
		delete parser;
		throw;
	}
	
	delete parser;
}

void DAG::add_chameleon(xsd_string s) {
	_chameleon.push_back(s);
}

void DAG::add_chameleon(vector<xsd_string> &s) {
	vector<xsd_string>::iterator it;
	for(it=s.begin();it!=s.end();it++) _chameleon.push_back(*it);
}

void DAG::readXML_chameleon(const char* xmlfile) {
	// Obtain the working directory
	string wdir = ".";
	char realwdir[PATH_MAX];
	realpath(wdir.c_str(),realwdir);
	wdir = realwdir;
	
	// Create a temporary sub-directory
	string tmpdir = wdir + "/gcat.tmp.XXXXXX";
	char ctmpdir[tmpdir.size()+1];
	int i;
	for(i=0;i<tmpdir.size();i++) ctmpdir[i] = tmpdir[i];
	ctmpdir[tmpdir.size()] = '\0';
	//strlcpy(ctmpdir,tmpdir.c_str(),tmpdir.size());
	char* rtmpdir = mkdtemp(ctmpdir);
	if(rtmpdir==NULL) {
		string errMsg = "Could not create temporary directory ";
		errMsg += tmpdir + ". " + strerror(errno);
		error(errMsg.c_str());
	}
	for(i=0;i<tmpdir.size();i++) tmpdir[i] = rtmpdir[i];
	
	// Write chameleon schemas to temporary directory
	vector<string> schema_fname(0);
	for(i=0;i<_chameleon.size();i++) {
		ostringstream schemafilename;
		schemafilename << tmpdir.c_str() << "/gcat.schema" << i << ".xsd";
		schema_fname.push_back(schemafilename.str());
		ofstream schemafile(schema_fname[i].c_str());
		schemafile << _chameleon[i];
		schemafile.close();
	}

	// Write parent schema
	ostringstream schemafilename;
	schemafilename << tmpdir.c_str() << "/gcat.schema.xsd";
	string xsd_file = schemafilename.str();
	ofstream schemafile(xsd_file.c_str());
	schemafile << "<?xml version=\"1.1\"?>\n\n<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" targetNamespace=\"http://www.danielwilson.me.uk/gcat\"\n";
	schemafile << "xmlns=\"http://www.danielwilson.me.uk/gcat\" elementFormDefault=\"qualified\">\n\n";
	for(i=0;i<_chameleon.size();i++) {
		schemafile << "\t<xs:include schemaLocation=\"" << schema_fname[i] << "\"/>\n";
	}
	schemafile << "\n</xs:schema>\n";
	schemafile.close();
	
	// URI for the parent schema
	string xsd_uri = string("http://www.danielwilson.me.uk/gcat ") + xsd_file;

	// Read in the XML file with the chameleon schema(s)
	try{
		readXML(xmlfile,xsd_uri.c_str());
	} catch (exception &e) {
		string errMsg = e.what();
		// Remove the temporary files
		if(remove(xsd_file.c_str())!=0) {
			errMsg += "\nAdditionally: could not delete temporary file ";
			errMsg += xsd_file + ". " + strerror(errno);
		}
		for(i=0;i<_chameleon.size();i++) {
			if(remove(schema_fname[i].c_str())!=0) {
				errMsg += "\nAdditionally: could not delete temporary file ";
				errMsg += schema_fname[i] + ". " + strerror(errno);
			}
		}
		if(rmdir(tmpdir.c_str())!=0) {
			errMsg += "\nAdditionally: could not delete temporary directory ";
			errMsg += tmpdir + ". " + strerror(errno);
		}
		error(errMsg.c_str());
	}
	catch (...) {
		string errMsg = "Unknown exception";
		// Remove the temporary files
		if(remove(xsd_file.c_str())!=0) {
			errMsg += "\nAdditionally: could not delete temporary file ";
			errMsg += xsd_file + ". " + strerror(errno);
		}
		for(i=0;i<_chameleon.size();i++) {
			if(remove(schema_fname[i].c_str())!=0) {
				errMsg += "\nAdditionally: could not delete temporary file ";
				errMsg += schema_fname[i] + ". " + strerror(errno);
			}
		}
		if(rmdir(tmpdir.c_str())!=0) {
			errMsg += "\nAdditionally: could not delete temporary directory ";
			errMsg += tmpdir + ". " + strerror(errno);
		}
		error(errMsg.c_str());
	}
	string errMsg = "";
	// Remove the temporary files                                                                                                                                     
	if(remove(xsd_file.c_str())!=0) {
	  errMsg += "Could not delete temporary file ";
	  errMsg += xsd_file + ". " + strerror(errno);
	}
	for(i=0;i<_chameleon.size();i++) {
	  if(remove(schema_fname[i].c_str())!=0) {
	    errMsg += "Could not delete temporary file ";
	    errMsg += schema_fname[i] + ". " + strerror(errno);
	  }
	}
	if(rmdir(tmpdir.c_str())!=0) {
	  errMsg += "Could not delete temporary directory ";
	  errMsg += tmpdir + ". " + strerror(errno);
	}
	if(errMsg!="") error(errMsg.c_str());
}

void DAG::readXML_libraries(const char* xmlfile) {
	// Obtain the working directory
	string wdir = ".";
	char realwdir[PATH_MAX];
	realpath(wdir.c_str(),realwdir);
	wdir = realwdir;
	
	// Create a temporary sub-directory
	string tmpdir = wdir + "/gcat.tmp.XXXXXX";
	char ctmpdir[tmpdir.size()+1];
	int i;
	for(i=0;i<tmpdir.size();i++) ctmpdir[i] = tmpdir[i];
	ctmpdir[tmpdir.size()] = '\0';
	//strlcpy(ctmpdir,tmpdir.c_str(),tmpdir.size());
	char* rtmpdir = mkdtemp(ctmpdir);
	if(rtmpdir==NULL) {
		string errMsg = "Could not create temporary directory ";
		errMsg += tmpdir + ". " + strerror(errno);
		error(errMsg.c_str());
	}
	for(i=0;i<tmpdir.size();i++) tmpdir[i] = rtmpdir[i];
	
	// Write skeleton schema to temporary directory
	ostringstream skeletonfilename;
	skeletonfilename << tmpdir.c_str() << "/gcat.skeleton.xsd";
	ofstream skeletonschema(skeletonfilename.str().c_str());
	skeletonschema << load_gcat_core_skeleton_schema();
	skeletonschema.close();
	
	// First pass: read libraries using skeleton schema
	string xsd_uri = string("http://www.danielwilson.me.uk/gcat ") + skeletonfilename.str();
	try{
		// This function employs gcatLibrary_XMLParser rather than topLevel_XMLParser
		readXML_firstpass(xmlfile,xsd_uri.c_str());
	} catch (exception &e) {
		string errMsg = e.what();
		// Remove the temporary files
		if(remove(skeletonfilename.str().c_str())!=0) {
			errMsg += "\nAdditionally: could not delete temporary file ";
			errMsg += skeletonfilename.str() + ". " + strerror(errno);
		}
		if(rmdir(tmpdir.c_str())!=0) {
			errMsg += "\nAdditionally: could not delete temporary directory ";
			errMsg += tmpdir + ". " + strerror(errno);
		}
		error(errMsg.c_str());
	}
	catch (...) {
		string errMsg = "Unknown exception";
		// Remove the temporary files
		if(remove(skeletonfilename.str().c_str())!=0) {
			errMsg += "\nAdditionally: could not delete temporary file ";
			errMsg += skeletonfilename.str() + ". " + strerror(errno);
		}
		if(rmdir(tmpdir.c_str())!=0) {
			errMsg += "\nAdditionally: could not delete temporary directory ";
			errMsg += tmpdir + ". " + strerror(errno);
		}
		error(errMsg.c_str());
	}	
	
	// Write chameleon schemas to temporary directory
	vector<string> schema_fname(0);
	for(i=0;i<_chameleon.size();i++) {
		ostringstream schemafilename;
		schemafilename << tmpdir.c_str() << "/gcat.schema" << i << ".xsd";
		schema_fname.push_back(schemafilename.str());
		ofstream schemafile(schema_fname[i].c_str());
		schemafile << _chameleon[i];
		schemafile.close();
	}
	
	// Write parent schema
	ostringstream schemafilename;
	schemafilename << tmpdir.c_str() << "/gcat.schema.xsd";
	string xsd_file = schemafilename.str();
	ofstream schemafile(xsd_file.c_str());
	schemafile << "<?xml version=\"1.1\"?>\n\n<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" targetNamespace=\"http://www.danielwilson.me.uk/gcat\"\n";
	schemafile << "xmlns=\"http://www.danielwilson.me.uk/gcat\" elementFormDefault=\"qualified\">\n\n";
	for(i=0;i<_chameleon.size();i++) {
		schemafile << "\t<xs:include schemaLocation=\"" << schema_fname[i] << "\"/>\n";
	}
	schemafile << "\n</xs:schema>\n";
	schemafile.close();
	
	// Second pass: read in the XML file with the chameleon schema(s)
	xsd_uri = string("http://www.danielwilson.me.uk/gcat ") + xsd_file;
	try{
		readXML(xmlfile,xsd_uri.c_str());
	} catch (exception &e) {
		string errMsg = e.what();
		// Remove the temporary files
		if(remove(skeletonfilename.str().c_str())!=0) {
			errMsg += "\nAdditionally: could not delete temporary file ";
			errMsg += skeletonfilename.str() + ". " + strerror(errno);
		}
		if(remove(xsd_file.c_str())!=0) {
			errMsg += "\nAdditionally: could not delete temporary file ";
			errMsg += xsd_file + ". " + strerror(errno);
		}
		for(i=0;i<_chameleon.size();i++) {
			if(remove(schema_fname[i].c_str())!=0) {
				errMsg += "\nAdditionally: could not delete temporary file ";
				errMsg += schema_fname[i] + ". " + strerror(errno);
			}
		}
		if(rmdir(tmpdir.c_str())!=0) {
			errMsg += "\nAdditionally: could not delete temporary directory ";
			errMsg += tmpdir + ". " + strerror(errno);
		}
		error(errMsg.c_str());
	}
	catch (...) {
		string errMsg = "Unknown exception";
		// Remove the temporary files
		if(remove(skeletonfilename.str().c_str())!=0) {
			errMsg += "\nAdditionally: could not delete temporary file ";
			errMsg += skeletonfilename.str() + ". " + strerror(errno);
		}
		if(remove(xsd_file.c_str())!=0) {
			errMsg += "\nAdditionally: could not delete temporary file ";
			errMsg += xsd_file + ". " + strerror(errno);
		}
		for(i=0;i<_chameleon.size();i++) {
			if(remove(schema_fname[i].c_str())!=0) {
				errMsg += "\nAdditionally: could not delete temporary file ";
				errMsg += schema_fname[i] + ". " + strerror(errno);
			}
		}
		if(rmdir(tmpdir.c_str())!=0) {
			errMsg += "\nAdditionally: could not delete temporary directory ";
			errMsg += tmpdir + ". " + strerror(errno);
		}
		error(errMsg.c_str());
	}
	string errMsg = "";
	// Remove the temporary files                                                                                                                                     
	if(remove(skeletonfilename.str().c_str())!=0) {
	  errMsg += "Could not delete temporary file ";
	  errMsg += skeletonfilename.str() + ". " + strerror(errno);
	}
	if(remove(xsd_file.c_str())!=0) {
	  errMsg += "Could not delete temporary file ";
	  errMsg += xsd_file + ". " + strerror(errno);
	}
	for(i=0;i<_chameleon.size();i++) {
	  if(remove(schema_fname[i].c_str())!=0) {
	    errMsg += "Could not delete temporary file ";
	    errMsg += schema_fname[i] + ". " + strerror(errno);
	  }
	}
	if(rmdir(tmpdir.c_str())!=0) {
	  errMsg += "Could not delete temporary directory ";
	  errMsg += tmpdir + ". " + strerror(errno);
	}
	if(errMsg!="") error(errMsg.c_str());
}

// Set the root element
void DAG::add_root_element(string s) {
	topLevel_XMLParser::add_child(s,&topLevel_XMLParser::factory);
}

// Enable libraries
void DAG::enable_libraries(){
	topLevel_XMLParser::add_child("libraries",&topLevel_XMLParser::factory);
	topLevel_XMLParser::add_child("library",&topLevel_XMLParser::factory);
}

xsd_string load_library(const char* filename) {
	void* handle = dlopen(filename,RTLD_LAZY);
	if(!handle) {
		string errMsg = "load_library(): Error when loading library: ";
		errMsg += filename;
		errMsg += ". Could not open dynamic library.\n";
		const char* dlerrMsg = dlerror();
		errMsg += dlerrMsg;
		error(errMsg.c_str());
	}
	xsd_string (*f)() = (xsd_string (*)()) dlsym(handle,"load_gcat_library");
	if(!f) {
		string errMsg = "load_library(): Error when loading library: ";
		errMsg += filename;
		errMsg += ". Could not locate load_gcat_library function";
		error(errMsg.c_str());
	}
	return (*f)();
}

xsd_string load_gcat_core_library() {
	LoadRandomVariablesXML();
	LoadTransformationsXML();
	LoadDistributionsXML();
	LoadInferenceXML();
	string s(gcat_core1_0_xsd_len,' ');
	unsigned int i;
	for(i=0;i<gcat_core1_0_xsd_len;i++) s[i] = gcat_core1_0_xsd[i];
	return s;
}	

xsd_string load_gcat_core_skeleton_schema() {
	string s(gcat_skeleton1_0_xsd_len,' ');
	unsigned int i;
	for(i=0;i<gcat_skeleton1_0_xsd_len;i++) s[i] = gcat_skeleton1_0_xsd[i];
	return s;
}	
	
} // namespace gcat
