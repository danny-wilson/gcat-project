/*  Copyright 2012 Daniel Wilson.
 *
 *  DAG.h
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
#ifndef _DAG_H_
#define _DAG_H_
#include <set>
#include <map>
#include <vector>
#include <string>
#include <mydouble.h>
#include <iostream>
#include <random.h>
#include <exception>

namespace gcat {

class Variable;
class RandomVariable;
class Distribution;
class Transformation;
class CompoundDistribution;
class Parameter;

// Functions that return this derived class are assumed to:
//   (1) That they return an xsd as an xsd_string type
//   (2) That they load into memory all necessary code for reading that xsd
// Further, it is assumed that dynamically loaded shared libraries have the following function:
//   (3) xsd_string load_gcat_library()
class xsd_string : public std::string {
public:
	xsd_string() : std::string() {};
	xsd_string(const std::string& s) : std::string(s) {};
	xsd_string(const std::string& str, size_t pos, size_t n = npos) : std::string(str, pos, n) {};
	xsd_string(const char* s, size_t n) : std::string(s,n) {};
	xsd_string(const char* s) : std::string(s) {};
	xsd_string(size_t n, char c) : std::string(n,c) {};
	~xsd_string() {};
};

class InferenceTechnique {
public:
	InferenceTechnique();
	virtual ~InferenceTechnique();
	virtual void perform_inference() = 0;
};

class DAG {
protected:
	// List of random variables and an index by name
	std::set< RandomVariable* > _random_variable;
	std::map< std::string, RandomVariable* > _random_variable_index;
	// Indicator of whether each variable is constant (i.e. its value must not be changed) *** IS THIS CONSTRAINT IMPLEMENTED? ***
	std::map< RandomVariable*, bool > _random_variable_is_constant;

	// List of variables and an index by name
	std::set< Transformation* > _transformation;
	std::map< std::string, Transformation* > _transformation_index;
	
	// List of distributions and an index by name
	std::set< Distribution* > _distribution;
	std::map< std::string, Distribution* > _distribution_index;
	
	// Indicator: has the DAG been connected using the connect_DAG() function
	bool _connected;

	// List of distributions, by name, pertaining to random variables, the distribution name concerned, and an index by random variable name
	std::vector< std::string > _parent_of_random_variable_distribution_name;
	std::vector< std::string > _parent_of_random_variable_parent_name;
	std::multimap< std::string, int > _parent_of_random_variable_index;

	// List of variables (RVs/transformations), by name, parameterising transformations, the parameter name concerned, and an index by transformation name
	std::vector< std::string > _parent_of_transformation_variable_name;
	std::vector< std::string > _parent_of_transformation_parameter_name;
	std::multimap< std::string, int > _parent_of_transformation_index;

	// List of variables (RVs/transformations), by name, parameterising distributions, the parameter name concerned, and an index by distribution name
	std::vector< std::string > _parent_of_distribution_variable_name;
	std::vector< std::string > _parent_of_distribution_parameter_name;
	std::multimap< std::string, int > _parent_of_distribution_index;
	
	// List of distributions, by name, pertaining to compound distributions, the distribution name concerned, and an index by compound distribution name
	std::vector< std::string > _parent_of_compound_distribution_distribution_name;
	std::vector< std::string > _parent_of_compound_distribution_parent_name;
	std::multimap< std::string, int > _parent_of_compound_distribution_index;

	// Indicator: is the DAG valid?
	bool _valid;
	// Pointer to the method of inference
	InferenceTechnique* _inference_technique;
	// Flag: attempt all likelihood evaluations even if one returns zero?
	bool _attempt_all_likelihoods;
	
	mydouble _last_likelihood;
	
	// Chameleon schemas, stored as strings
	std::vector< xsd_string > _chameleon;
	
public:
	// Constructor
	DAG();
	// Copy constructor
	DAG(const DAG& dag);
	// Destructor: DAG will destroy all its variables and distributions
	virtual ~DAG();
	// Is a component name unique?
	bool unique_name(std::string name);
	// Add a random variable
	Variable* add_random_variable(RandomVariable* var, const bool constant="false");
	// Make a random variable a constant
	void set_constant(std::string rvar);
	// Add a transformation
	Variable* add_transformation(Transformation* trans);
	// Add a distribution
	Distribution* add_distribution(Distribution* dist);
	// Make note of the intention to connect a variable to its parent distribution
	void assign_distribution_to_random_variable(std::string rvar, std::string parent_name, std::string dist);
	// Make note of the intention to connect a transformation to its parent variable
	void assign_parameter_to_transformation(std::string trans, std::string parameter_name, std::string var);
	// Make note of the intention to connect a distribution to its parent variable
	void assign_parameter_to_distribution(std::string dist, std::string parameter_name, std::string var);
	// Make note of the intention to connect a (compound) distribution to its parent distribution
	void assign_distribution_to_compound_distribution(std::string child, std::string parent_name, std::string parent);
	// Get a pointer to a named variable
	Variable* get_variable(std::string name);
	// Get a pointer to a named random variable
	RandomVariable* get_random_variable(std::string name);
	// Get a pointer to a named transformation
	Transformation* get_transformation(std::string name);
	// Get a pointer to a named distribution
	Distribution* get_distribution(std::string name);
	// Get a pointer to a named parameter (i.e. RandomVariable or Transformation)
	Parameter* get_parameter(std::string name);
	// Is a named variable constant? (i.e. the value not to be changed)
	bool is_constant_variable(std::string name);
	// Make the intended connections
	void connect_graph();
	// Check the validity of the DAG
	void check_validity();
	// Is valid?
	bool is_valid();
	// Log-likelihood
	double log_likelihood();
	mydouble likelihood();
	mydouble last_likelihood();
	// Read in DAG from XML file, with external xsd file
	void readXML(const char* xmlfile, const char* xsdfile);
	// Read in DAG from XML file that specifies its own schema
	void readXML(const char* xmlfile);
	// Read in DAG from XML file, with external xsd file, employing topLevelLibrary_XMLParser
	void readXML_firstpass(const char* xmlfile, const char* xsdfile);
	// Specify one or more chameleon schemas (calling this function implies the code to read the schemas is loaded)
	void add_chameleon(xsd_string s);
	void add_chameleon(std::vector<xsd_string> &s);
	// Read in DAG from XML file, constructing a chameleon schema (calling this function implies the code to read the schemas is loaded)
	void readXML_chameleon(const char* xmlfile);
	// Read in DAG from XML file with libraries (two pass, first pass reads libraries, chameleon schemas and associated code)
	void readXML_libraries(const char* xmlfile);
	// Set the root element
	void add_root_element(std::string s);
	// Enable libraries
	void enable_libraries();
	// Set the inference technique
	void set_inference_technique(InferenceTechnique* inference_technique);
	// Get the inference technique
	InferenceTechnique* get_inference_technique();
	// Perform inference
	void perform_inference();
	// Check casts
	void check_casts();
	// Set the flag to determine whether all likelihoods are calculated even one returns zero
	void set_attempt_all_likelihoods(const bool attempt_all_likelihoods);
	
	void ready();
	void reset_all();
};

xsd_string load_library(const char* filename);
xsd_string load_gcat_core_library();
xsd_string load_gcat_core_skeleton_schema();

} // namespace gcat

#endif //_DAG_H_
