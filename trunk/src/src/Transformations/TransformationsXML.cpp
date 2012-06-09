/*  Copyright 2012 Daniel Wilson.
 *
 *  TransformationsXML.cpp
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
#include <Transformations/TransformationsXML.h>
#include <Transformations/ContinuousMosaicNumBlocks.h>
#include <Transformations/ContinuousVectorElement.h>
#include <Transformations/ExponentialTransform.h>
#include <Transformations/ExponentialQuantileVector.h>
#include <Transformations/InverseLogitTransform.h>
#include <Transformations/LogLikelihoodTransform.h>
#include <Transformations/ProductTransform.h>
#include <Transformations/SumTransform.h>
#include <DAG/RandomVariable.h>
#include <Properties/Length.h>
#include <RandomVariables/Continuous.h>
#include <Transformations/Conversions/Continuous2ContinuousMosaic.h>
#include <Transformations/Conversions/Continuous2ContinuousVector.h>
#include <Transformations/LinearMosaic.h>
#include <Transformations/FractionTransform.h>
#include <Transformations/AbsoluteTransform.h>
#include <Transformations/PowerTransform.h>
#include <Transformations/Concatenate.h>

namespace gcat {

to_continuous_mosaic_XMLParser::to_continuous_mosaic_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<to_continuous_mosaic_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"id","x","length"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// First work out the length
	int int_length;
	if(!from_string<int>(int_length,sattr[2])) {
		RandomVariable* rv = getDAG()->get_random_variable(sattr[2]);
		if(rv==0) error("to_continuous_mosaic_XMLParser: could not convert length to int nor find named variable");
		LengthProperty* lp = dynamic_cast<LengthProperty*>(rv);
		if(lp==0) error("to_continuous_mosaic_XMLParser: named variable does not have length property");
		int_length = lp->length();
	}
	// Obtain random variable
	Variable* v = getDAG()->get_variable(sattr[1]);
	// Test if already of desired type
	if(dynamic_cast<ContinuousMosaicVariable*>(v)!=0) {
		string errMsg = "to_continuous_mosaic_XMLParser: variable " + sattr[1] + " is already of desire type";
		error(errMsg.c_str());
	}
	// Try to convert from ContinuousVariable
	ContinuousVariable* cv = dynamic_cast<ContinuousVariable*>(v);
	if(cv!=0) {
		new ContinuousVariable2ContinuousMosaicVariable(sattr[0],getDAG(),int_length);
		getDAG()->assign_parameter_to_transformation(sattr[0],attrNames[1],sattr[1]);
		return;
	}
	// Try other conversions here, in decreasing order of preference
	string errMsg = "to_continuous_mosaic_XMLParser: could not convert variable " + sattr[1] + " of type " + v->type() + " to desired type";
	error(errMsg.c_str());
}

to_continuous_vector_XMLParser::to_continuous_vector_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<to_continuous_vector_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"id","x","length"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// First work out the length
	int int_length;
	if(!from_string<int>(int_length,sattr[2])) {
		RandomVariable* rv = getDAG()->get_random_variable(sattr[2]);
		if(rv==0) error("to_continuous_vector_XMLParser: could not convert length to int nor find named variable");
		LengthProperty* lp = dynamic_cast<LengthProperty*>(rv);
		if(lp==0) error("to_continuous_vector_XMLParser: named variable does not have length property");
		int_length = lp->length();
	}
	// Obtain random variable
	Variable* v = getDAG()->get_variable(sattr[1]);
	// Test if already of desired type
	if(dynamic_cast<ContinuousVectorVariable*>(v)!=0) {
		string errMsg = "to_continuous_vector_XMLParser: variable " + sattr[1] + " is already of desired type";
		error(errMsg.c_str());
	}
	// Try to convert from ContinuousVariable
	ContinuousVariable* cv = dynamic_cast<ContinuousVariable*>(v);
	if(cv!=0) {
		new ContinuousVariable2ContinuousVectorVariable(sattr[0],getDAG(),int_length);
		getDAG()->assign_parameter_to_transformation(sattr[0],attrNames[1],sattr[1]);
		return;
	}
	// Try other conversions here, in decreasing order of preference
	string errMsg = "to_continuous_vector_XMLParser: could not convert variable " + sattr[1] + " of type " + v->type() + " to desired type";
	error(errMsg.c_str());
}

abs_transform_XMLParser::abs_transform_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<abs_transform_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 2;
	const char* attrNames[nattr] = {"id","x"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	new AbsoluteTransform(sattr[0],getDAG());
	getDAG()->assign_parameter_to_transformation(sattr[0],attrNames[1],sattr[1]);
}

concatenate_transform_XMLParser::concatenate_transform_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<concatenate_transform_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 2;
	const char* attrNames[nattr] = {"id","length"};
	sattr = attributesToStrings(nattr,attrNames,attrs);
	// Don't instantiate the variable until the values have been read in
}

void concatenate_transform_XMLParser::implement_characters(const XMLCh* const chars, const XMLSize_t length) {
	// Convert value to double
	int int_length;
	if(!from_string<int>(int_length,sattr[1])) error("concatenate_transform_XMLParser: could not convert length to int");
	string message = "";
	int i;
	for(i=0;i<length;i++) message += chars[i];
	vector<string> operands;
	if(!string_to_vector(operands,message)) error("concatenate_transform_XMLParser: error interpretting input");
	if(operands.size()==0) error("concatenate_transform_XMLParser: no items entered");
	new ConcatenateTransform(operands.size(),int_length,sattr[0],getDAG());
	for(i=0;i<operands.size();i++) {
		stringstream s;
		s << "item" << i;
		getDAG()->assign_parameter_to_transformation(sattr[0],s.str(),operands[i]);
	}
}
continuous_mosaic_num_blocks_XMLParser::continuous_mosaic_num_blocks_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<continuous_mosaic_num_blocks_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 2;
	const char* attrNames[nattr] = {"id","continuous_mosaic"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	new ContinuousMosaicNumBlocks(sattr[0],getDAG());
	getDAG()->assign_parameter_to_transformation(sattr[0],attrNames[1],sattr[1]);
}

continuous_vector_element_XMLParser::continuous_vector_element_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<continuous_vector_element_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"id","vector","element"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// Convert value to double
	int int_element;
	if(!from_string<int>(int_element,sattr[2])) error("continuous_vector_element_XMLParser: could not convert element to int");
	new ContinuousVectorElement(int_element,sattr[0],getDAG());
	getDAG()->assign_parameter_to_transformation(sattr[0],attrNames[1],sattr[1]);
}

exp_transform_XMLParser::exp_transform_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<exp_transform_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 2;
	const char* attrNames[nattr] = {"id","exponent"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	new ExponentialTransform(sattr[0],getDAG());
	getDAG()->assign_parameter_to_transformation(sattr[0],attrNames[1],sattr[1]);
}

exponential_quantile_function_vector_XMLParser::exponential_quantile_function_vector_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<exponential_quantile_function_vector_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"id","lambda","quantile"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// lambda can be specified as numeric, in which case it must be instantiated as a Variable
	double double_lambda;
	if(from_string<double>(double_lambda,sattr[1])) {
		// Internally-generated name
		sattr[1] = "_" + sattr[0] + "." + attrNames[1];
		new ContinuousRV(sattr[1],getDAG(),double_lambda);
		getDAG()->set_constant(sattr[1]);
	}
	// Automatically obtain length of the quantile mosaic
	int int_length;
	RandomVariable* rv = getDAG()->get_random_variable(sattr[2]);
	if(rv==0) error("exponential_quantile_function_vector_XMLParser: could not find named variable for quantile");
	LengthProperty* lp = dynamic_cast<LengthProperty*>(rv);
	if(lp==0) error("exponential_quantile_function_vector_XMLParser: named variable quantile does not have length property");
	int_length = lp->length();
	// Instantiate
	new ExponentialQuantileVectorTransform(int_length,sattr[0],getDAG());
	getDAG()->assign_parameter_to_transformation(sattr[0],attrNames[1],sattr[1]);
	getDAG()->assign_parameter_to_transformation(sattr[0],attrNames[2],sattr[2]);
}

fraction_transform_XMLParser::fraction_transform_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<fraction_transform_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"id","numerator","denominator"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	new FractionTransform(sattr[0],getDAG());
	getDAG()->assign_parameter_to_transformation(sattr[0],attrNames[1],sattr[1]);
	getDAG()->assign_parameter_to_transformation(sattr[0],attrNames[2],sattr[2]);
}

inverse_logit_transform_XMLParser::inverse_logit_transform_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<inverse_logit_transform_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 2;
	const char* attrNames[nattr] = {"id","p"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	new InverseLogitTransform(sattr[0],getDAG());
	getDAG()->assign_parameter_to_transformation(sattr[0],attrNames[1],sattr[1]);
}

linear_mosaic_transform_XMLParser::linear_mosaic_transform_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<linear_mosaic_transform_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 4;
	const char* attrNames[nattr] = {"id","mean","sd","z"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// mean and sd can be specified as numeric, in which case they must be instantiated as Variables
	double double_mean;
	if(from_string<double>(double_mean,sattr[1])) {
		// Internally-generated name
		sattr[1] = "_" + sattr[0] + "." + attrNames[1];
		new ContinuousRV(sattr[1],getDAG(),double_mean);
		getDAG()->set_constant(sattr[1]);
	}
	double double_sd;
	if(from_string<double>(double_sd,sattr[2])) {
		// Internally-generated name
		sattr[2] = "_" + sattr[0] + "." + attrNames[2];
		new ContinuousRV(sattr[2],getDAG(),double_sd);
		getDAG()->set_constant(sattr[2]);
	}
	// Automatically obtain length of the quantile mosaic
	int int_length;
	RandomVariable* rv = getDAG()->get_random_variable(sattr[3]);
	if(rv==0) error("normal_quantile_function_mosaic_XMLParser: could not find named variable for z");
	LengthProperty* lp = dynamic_cast<LengthProperty*>(rv);
	if(lp==0) error("normal_quantile_function_mosaic_XMLParser: named variable z does not have length property");
	int_length = lp->length();
	// Instantiate
	new LinearMosaicTransform(int_length,sattr[0],getDAG());
	getDAG()->assign_parameter_to_transformation(sattr[0],attrNames[1],sattr[1]);
	getDAG()->assign_parameter_to_transformation(sattr[0],attrNames[2],sattr[2]);
	getDAG()->assign_parameter_to_transformation(sattr[0],attrNames[3],sattr[3]);
}

log_likelihood_transform_XMLParser::log_likelihood_transform_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<log_likelihood_transform_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 2;
	const char* attrNames[nattr] = {"id","rv"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	new LogLikelihoodTransform(sattr[0],getDAG());
	getDAG()->assign_parameter_to_transformation(sattr[0],attrNames[1],sattr[1]);
}

power_transform_XMLParser::power_transform_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<power_transform_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"id","base","exponent"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// base and exponent can be specified as numeric, in which case they must be instantiated as Variables
	double double_base;
	if(from_string<double>(double_base,sattr[1])) {
		// Internally-generated name
		sattr[1] = "_" + sattr[0] + "." + attrNames[1];
		new ContinuousRV(sattr[1],getDAG(),double_base);
		getDAG()->set_constant(sattr[1]);
	}
	double double_exponent;
	if(from_string<double>(double_exponent,sattr[2])) {
		// Internally-generated name
		sattr[2] = "_" + sattr[0] + "." + attrNames[2];
		new ContinuousRV(sattr[2],getDAG(),double_exponent);
		getDAG()->set_constant(sattr[2]);
	}
	new PowerTransform(sattr[0],getDAG());
	getDAG()->assign_parameter_to_transformation(sattr[0],attrNames[1],sattr[1]);
	getDAG()->assign_parameter_to_transformation(sattr[0],attrNames[2],sattr[2]);
}

product_transform_XMLParser::product_transform_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<product_transform_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 1;
	const char* attrNames[nattr] = {"id"};
	sattr = attributesToStrings(nattr,attrNames,attrs);
	// Don't instantiate the variable until the values have been read in
}

void product_transform_XMLParser::implement_characters(const XMLCh* const chars, const XMLSize_t length) {
	string message = "";
	int i;
	for(i=0;i<length;i++) message += chars[i];
	vector<string> operands;
	if(!string_to_vector(operands,message)) error("product_transform_XMLParser: error interpretting input");
	if(operands.size()==0) error("product_transform_XMLParser: no operands entered");
	new ProductTransform(operands.size(),sattr[0],getDAG());
	for(i=0;i<operands.size();i++) {
		stringstream s;
		s << "operand" << i;
		getDAG()->assign_parameter_to_transformation(sattr[0],s.str(),operands[i]);
	}
}

transformations_XMLParser::transformations_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<transformations_XMLParser>(master_parser,parent_parser) {
	// No attributes are taken
}

sum_transform_XMLParser::sum_transform_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<sum_transform_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 1;
	const char* attrNames[nattr] = {"id"};
	sattr = attributesToStrings(nattr,attrNames,attrs);
	// Don't instantiate the variable until the values have been read in
}

void sum_transform_XMLParser::implement_characters(const XMLCh* const chars, const XMLSize_t length) {
	string message = "";
	int i;
	for(i=0;i<length;i++) message += chars[i];
	vector<string> operands;
	if(!string_to_vector(operands,message)) error("sum_transform_XMLParser: error interpretting input");
	if(operands.size()==0) error("sum_transform_XMLParser: no operands entered");
	new SumTransform(operands.size(),sattr[0],getDAG());
	for(i=0;i<operands.size();i++) {
		stringstream s;
		s << "operand" << i;
		getDAG()->assign_parameter_to_transformation(sattr[0],s.str(),operands[i]);
	}
}

void LoadTransformationsXML() {
	topLevel_XMLParser::add_child("transformations",&transformations_XMLParser::factory);
	transformations_XMLParser::add_child("to_continuous_mosaic",&to_continuous_mosaic_XMLParser::factory);
	transformations_XMLParser::add_child("to_continuous_vector",&to_continuous_vector_XMLParser::factory);
	transformations_XMLParser::add_child("abs_transform",&abs_transform_XMLParser::factory);
	transformations_XMLParser::add_child("concatenate",&concatenate_transform_XMLParser::factory);
	transformations_XMLParser::add_child("continuous_mosaic_num_blocks",&continuous_mosaic_num_blocks_XMLParser::factory);
	transformations_XMLParser::add_child("continuous_vector_element",&continuous_vector_element_XMLParser::factory);
	transformations_XMLParser::add_child("exp_transform",&exp_transform_XMLParser::factory);
	transformations_XMLParser::add_child("exponential_quantile_function_vector",&exponential_quantile_function_vector_XMLParser::factory);
	transformations_XMLParser::add_child("fraction_transform",&fraction_transform_XMLParser::factory);
	transformations_XMLParser::add_child("inverse_logit_transform",&inverse_logit_transform_XMLParser::factory);
	transformations_XMLParser::add_child("linear_mosaic_transform",&linear_mosaic_transform_XMLParser::factory);
	transformations_XMLParser::add_child("log_likelihood_transform",&log_likelihood_transform_XMLParser::factory);
	transformations_XMLParser::add_child("power_transform",&power_transform_XMLParser::factory);
	transformations_XMLParser::add_child("product_transform",&product_transform_XMLParser::factory);
	transformations_XMLParser::add_child("sum_transform",&sum_transform_XMLParser::factory);
}
	
} // namespace gcat
