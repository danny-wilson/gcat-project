/*  Copyright 2012 Daniel Wilson.
 *
 *  RandomVariablesXML.cpp
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
#include <RandomVariables/RandomVariablesXML.h>
#include <Properties/Length.h>
#include <RandomVariables/Continuous.h>
#include <RandomVariables/ContinuousMosaic.h>
#include <RandomVariables/ContinuousVector.h>
#include <RandomVariables/Discrete.h>

namespace gcat {

continuous_scalar_XMLParser::continuous_scalar_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser, const bool constant) : DAGXMLParserTemplate<continuous_scalar_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"id","distribution","value"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// Convert value to double
	double double_val;
	if(!from_string<double>(double_val,sattr[2])) error("continous_scalar_XMLParser: could not convert value to double");
	// Instantiate the variable
	new ContinuousRV(sattr[0],getDAG(),double_val);
	if(sattr[1]!="") getDAG()->assign_distribution_to_random_variable(sattr[0],attrNames[1],sattr[1]);
	if(constant) getDAG()->set_constant(sattr[0]);
}

continuous_mosaic_XMLParser::continuous_mosaic_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser, const bool constant) : DAGXMLParserTemplate<continuous_mosaic_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 5;
	const char* attrNames[nattr] = {"id","distribution","length","boundaries","values"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// Convert length to int
	int int_length;
	if(!from_string<int>(int_length,sattr[2])) {
		RandomVariable* rv = getDAG()->get_random_variable(sattr[2]);
		if(rv==0) error("continuous_mosaic_XMLParser: could not convert length to int nor find named variable");
		LengthProperty* lp = dynamic_cast<LengthProperty*>(rv);
		if(lp==0) error("continuous_mosaic_XMLParser: named variable does not have length property");
		int_length = lp->length();
	}
	if(int_length<=0) error("continuous_mosaic_XMLParser: length must be a positive integer");
	// Get vector<int> from boundaries
	vector<int> vint_boundaries;
	if(!string_to_vector<int>(vint_boundaries,sattr[3])) error("continuous_mosaic_XMLParser: could not convert boundaries to int");
	// Get vector<double> from values
	vector<double> vdouble_values;
	if(!string_to_vector<double>(vdouble_values,sattr[4])) error("continuous_mosaic_XMLParser: could not convert values to double");
	// Instantiate the variable
	new ContinuousMosaicRV(int_length,sattr[0],getDAG(),vint_boundaries,vdouble_values);
	if(sattr[1]!="") getDAG()->assign_distribution_to_random_variable(sattr[0],attrNames[1],sattr[1]);
	if(constant) getDAG()->set_constant(sattr[0]);
}

discrete_scalar_XMLParser::discrete_scalar_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser, const bool constant) : DAGXMLParserTemplate<discrete_scalar_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"id","distribution","value"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// Convert value to int
	int int_val;
	if(!from_string<int>(int_val,sattr[2])) error("discrete_scalar_XMLParser: could not convert value to int");
	// Instantiate the variable
	new DiscreteRV(sattr[0],getDAG(),int_val);
	if(sattr[1]!="") getDAG()->assign_distribution_to_random_variable(sattr[0],attrNames[1],sattr[1]);
	if(constant) getDAG()->set_constant(sattr[0]);
}

continuous_vector_XMLParser::continuous_vector_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser, const bool constant) : DAGXMLParserTemplate<continuous_vector_XMLParser>(master_parser,parent_parser) {
	_constant = constant;
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"id","distribution","length"};
	sattr = attributesToStrings(nattr,attrNames,attrs);
	// Don't instantiate the variable until the values have been read in
}

void continuous_vector_XMLParser::implement_characters(const XMLCh* const chars, const XMLSize_t length) {
	string message = "";
	int i;
	for(i=0;i<length;i++) message += chars[i];
	istringstream oss(message);
	vector<double> val(0);
	double val_j;
	while(!(oss >> val_j).fail()) {
		val.push_back(val_j);
	}
	if(val.size()==0) error("continuous_vector_XMLParser: no values entered");
	int int_length;
	if(sattr[2]=="") int_length = val.size();
	else if(!from_string<int>(int_length,sattr[2])) error("continuous_vector_XMLParser: could not convert length to int");
	if(int_length!=val.size()) {
		if(val.size()==1) val = vector<double>(int_length,val[0]);
		else error("continuous_vector_XMLParser: stated length and input variables incompatible");
	}	
	new ContinuousVectorRV(int_length,sattr[0],getDAG(),val);
	if(sattr[1]!="") getDAG()->assign_distribution_to_random_variable(sattr[0],"distribution",sattr[1]);
	if(_constant) getDAG()->set_constant(sattr[0]);
}

iid_continuous_scalar_XMLParser::iid_continuous_scalar_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<iid_continuous_scalar_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"id","distribution","length"};
	sattr = attributesToStrings(nattr,attrNames,attrs);
	// Don't instantiate the variable until the values have been read in
}

void iid_continuous_scalar_XMLParser::implement_characters(const XMLCh* const chars, const XMLSize_t length) {
	string message = "";
	int i;
	for(i=0;i<length;i++) message += chars[i];
	istringstream oss(message);
	vector<double> val(0);
	double val_j;
	while(!(oss >> val_j).fail()) {
		val.push_back(val_j);
	}
	if(val.size()==0) error("iid_continuous_scalar_XMLParser: no values entered");
	int int_length;
	if(sattr[2]=="") int_length = val.size();
	else if(!from_string<int>(int_length,sattr[2])) error("iid_continuous_scalar_XMLParser: could not convert length to int");
	if(int_length!=val.size()) {
		if(val.size()==1) val = vector<double>(int_length,val[0]);
		else error("iid_continuous_scalar_XMLParser: stated length and input variables incompatible");
	}	
	// Instantiate the variables: manually create a series of ContinuousUnivariateVariable objects
	// Since it won't be possible to refer to these variables by their name, force them to be constant
	int j;
	for(j=0;j<val.size();j++) {
		// Internally-generated name
		stringstream name;
		name << "_" << sattr[0] << "[" << j << "]";
		new ContinuousRV(name.str(),getDAG(),val[j]);
		if(sattr[1]!="") getDAG()->assign_distribution_to_random_variable(name.str(),"distribution",sattr[1]);
		getDAG()->set_constant(name.str());
	}
}

iid_discrete_scalar_XMLParser::iid_discrete_scalar_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<iid_discrete_scalar_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 2;
	const char* attrNames[nattr] = {"id","distribution"};
	sattr = attributesToStrings(nattr,attrNames,attrs);
	// Don't instantiate the variable until the values have been read in
}

void iid_discrete_scalar_XMLParser::implement_characters(const XMLCh* const chars, const XMLSize_t length) {
	string message = "";
	int i;
	for(i=0;i<length;i++) message += chars[i];
	istringstream oss(message);
	vector<int> val(0);
	int val_j;
	while(!(oss >> val_j).fail()) {
		val.push_back(val_j);
	}
	if(val.size()==0) error("iid_discrete_scalar_XMLParser: no values entered");
	// Instantiate the variables: manually create a series of ContinuousUnivariateVariable objects
	// Since it won't be possible to refer to these variables by their name, force them to be constant
	int j;
	for(j=0;j<val.size();j++) {
		// Internally-generated name
		stringstream name;
		name << "_" << sattr[0] << "[" << j << "]";
		new DiscreteRV(name.str(),getDAG(),val[j]);
		if(sattr[1]!="") getDAG()->assign_distribution_to_random_variable(name.str(),"distribution",sattr[1]);
		getDAG()->set_constant(name.str());
	}
}

void LoadRandomVariablesXML() {
	topLevel_XMLParser::add_child("data",&data_XMLParser::factory);
	data_XMLParser::add_child("continuous_mosaic",&continuous_mosaic_XMLParser::factory_constant);
	data_XMLParser::add_child("continuous_scalar",&continuous_scalar_XMLParser::factory_constant);
	data_XMLParser::add_child("continuous_vector",&continuous_vector_XMLParser::factory_constant);
	data_XMLParser::add_child("discrete_scalar",&discrete_scalar_XMLParser::factory_constant);
	data_XMLParser::add_child("iid_continuous_scalar",&iid_continuous_scalar_XMLParser::factory);
	data_XMLParser::add_child("iid_discrete_scalar",&iid_discrete_scalar_XMLParser::factory);

	topLevel_XMLParser::add_child("parameters",&parameters_XMLParser::factory);
	parameters_XMLParser::add_child("continuous_mosaic",&continuous_mosaic_XMLParser::factory);
	parameters_XMLParser::add_child("continuous_scalar",&continuous_scalar_XMLParser::factory);
	parameters_XMLParser::add_child("continuous_vector",&continuous_vector_XMLParser::factory);
	parameters_XMLParser::add_child("discrete_scalar",&discrete_scalar_XMLParser::factory);
	parameters_XMLParser::add_child("iid_continuous_scalar",&iid_continuous_scalar_XMLParser::factory);
	parameters_XMLParser::add_child("iid_discrete_scalar",&iid_discrete_scalar_XMLParser::factory);	
}
	
} // namespace gcat
