/*  Copyright 2012 Daniel Wilson.
 *
 *  DAG.cpp
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
#include <myerror.h>
#include <DAG/DAG.h>
#include <DAG/RandomVariable.h>
#include <DAG/Transformation.h>
#include <DAG/Distribution.h>
#include <DAG/CompoundDistribution.h>
#include <iostream>

using myutils::error;
using myutils::warning;
using std::pair;
using std::cout;

namespace gcat {
// Global variables
myutils::Random _ran;
int is_gsl_set_error_handler_off = 0;

DAG::DAG() : _connected(false), _valid(false), _inference_technique(0), _last_likelihood(0), _attempt_all_likelihoods(false) {
}

DAG::DAG(const DAG& dag) {
	error("DAG::DAG(const DAG&): copy constructor not implemented");
}

DAG::~DAG() {
	_valid = false;
	set< RandomVariable* >::iterator i;
	for(i=_random_variable.begin();i!=_random_variable.end();i++) {
		delete *i;
	}
	set< Transformation* >::iterator j;
	for(j=_transformation.begin();j!=_transformation.end();j++) {
		delete *j;
	}
	set< Distribution* >::iterator k;
	for(k=_distribution.begin();k!=_distribution.end();k++) {
		delete *k;
	}
	if(_inference_technique!=0) delete _inference_technique;
}

bool DAG::unique_name(string name) {
	map< string, RandomVariable* >::iterator rvi = _random_variable_index.find(name);
	if(rvi!=_random_variable_index.end()) return false;
	
	map< string, Transformation* >::iterator tri = _transformation_index.find(name);
	if(tri!=_transformation_index.end()) return false;

	map< string, Distribution* >::iterator dii = _distribution_index.find(name);
	if(dii!=_distribution_index.end()) return false;
	
	return true;
}

Variable* DAG::add_random_variable(RandomVariable* var, const bool constant) {
	_valid = false;
	if(var==0) error("DAG::add_random_variable(): variable not found");
	set< RandomVariable* >::iterator it = _random_variable.find(var);
	if(it!=_random_variable.end()) error("DAG::add_random_variable(): variable already added");
	if(!unique_name(var->name())) {
		string errTxt = "DAG::add_random_variable(): variable " + var->name() + " needs a unique name";
		error(errTxt.c_str());
	}
	_random_variable.insert(var);
	_random_variable_index.insert(pair< string, RandomVariable* >(var->name(),var));
	_random_variable_is_constant.insert(pair< RandomVariable*, bool >(var,constant));
	if(var->getDAG()!=this && var->getDAG()!=0) error("DAG::add_random_variable(): variable belongs to another DAG");
	var->setDAG(this);
	return var;
}

void DAG::set_constant(string name) {
	RandomVariable* var = get_random_variable(name);
	_random_variable_is_constant[var] = true;
}

Variable* DAG::add_transformation(Transformation* var) {
	_valid = false;
	if(var==0) error("DAG::add_transformation(): variable not found");
	set< Transformation* >::iterator it = _transformation.find(var);
	if(it!=_transformation.end()) error("DAG::add_transformation(): variable already added");
	if(!unique_name(var->name())) {
		string errTxt = "DAG::add_transformation(): variable " + var->name() + " needs a unique name";
		error(errTxt.c_str());
	}
	_transformation.insert(var);
	_transformation_index.insert(pair< string, Transformation* >(var->name(),var));
	if(var->getDAG()!=this && var->getDAG()!=0) error("DAG::add_transformation(): variable belongs to another DAG");
	var->setDAG(this);
	return var;
}

Distribution* DAG::add_distribution(Distribution* dist) {
	_valid = false;
	if(dist==0) error("DAG::add_distribution(): distribution not found");
//	dist = dynamic_cast<Distribution*>(dist);
//	if(dist==0) error("DAG::add_distribution(): dynamic cast problem");
	set< Distribution* >::iterator it = _distribution.find(dist);
	if(it!=_distribution.end()) error("DAG::add_distribution(): distribution already added");
	if(!unique_name(dist->name())) error("DAG::add_distribution(): distribution needs a unique name");
	_distribution.insert(dist);
	_distribution_index.insert(pair< string, Distribution* >(dist->name(),dist));
	if(dist->getDAG()!=this && dist->getDAG()!=0) error("DAG::add_distribution(): distribution belongs to another DAG");
	dist->setDAG(this);
	return dist;
}

void DAG::assign_distribution_to_random_variable(string var, string parent_name, string dist) {
	_valid = false;
	int ix = _parent_of_random_variable_parent_name.size();
	_parent_of_random_variable_index.insert(pair< string, int >(var,ix));
	_parent_of_random_variable_parent_name.push_back(parent_name);
	_parent_of_random_variable_distribution_name.push_back(dist);
}

void DAG::assign_parameter_to_transformation(string trans, string parameter_name, string var) {
	_valid = false;
	int ix = _parent_of_transformation_parameter_name.size();
	_parent_of_transformation_index.insert(pair< string, int >(trans,ix));
	_parent_of_transformation_parameter_name.push_back(parameter_name);
	_parent_of_transformation_variable_name.push_back(var);
}

void DAG::assign_parameter_to_distribution(string dist, string parameter_name, string var) {
	_valid = false;
	int ix = _parent_of_distribution_parameter_name.size();
	_parent_of_distribution_index.insert(pair< string, int >(dist,ix));
	_parent_of_distribution_parameter_name.push_back(parameter_name);
	_parent_of_distribution_variable_name.push_back(var);
}

void DAG::assign_distribution_to_compound_distribution(string child, string parent_name, string parent) {
	_valid = false;
	int ix = _parent_of_compound_distribution_parent_name.size();
	_parent_of_compound_distribution_index.insert(pair< string, int >(child,ix));
	_parent_of_compound_distribution_parent_name.push_back(parent_name);
	_parent_of_compound_distribution_distribution_name.push_back(parent);
}

Variable* DAG::get_variable(string name) {
	map< string, RandomVariable* >::iterator it = _random_variable_index.find(name);
	map< string, Transformation* >::iterator jt = _transformation_index.find(name);
	if(it!=_random_variable_index.end()) {
		return it->second;
	}
	else if(jt!=_transformation_index.end()) {
		return jt->second;
	}
	else {
		string errMsg = "DAG::get_variable(): not found: ";
		errMsg += name;
		error(errMsg.c_str());
	}
	return 0;
}

RandomVariable* DAG::get_random_variable(string name) {
	map< string, RandomVariable* >::iterator it = _random_variable_index.find(name);
	if(it==_random_variable_index.end()) {
		string errMsg = "DAG::get_random_variable(): not found: ";
		errMsg += name;
		error(errMsg.c_str());
	}
	return it->second;
}

Transformation* DAG::get_transformation(string name) {
	map< string, Transformation* >::iterator it = _transformation_index.find(name);
	if(it==_transformation_index.end()) {
		string errMsg = "DAG::get_transformation(): not found: ";
		errMsg += name;
		error(errMsg.c_str());
	}
	return it->second;
}

Distribution* DAG::get_distribution(string name) {
	map< string, Distribution* >::iterator it = _distribution_index.find(name);
	if(it==_distribution_index.end()) {
		string errMsg = "DAG::get_distribution(): not found: ";
		errMsg += name;
		error(errMsg.c_str());
	}
	return it->second;
}

Parameter* DAG::get_parameter(string name) {
	map< string, RandomVariable* >::iterator it = _random_variable_index.find(name);
	if(it==_random_variable_index.end()) {
		map< string, Transformation* >::iterator jt = _transformation_index.find(name);
		if(jt==_transformation_index.end()) {
			string errMsg = "DAG::get_parameter(): not found: ";
			errMsg += name;
			error(errMsg.c_str());
		}
		return dynamic_cast<Parameter*>(jt->second);
	}
	return dynamic_cast<Parameter*>(it->second);
}

// Constants can have distributions (e.g. data) but cannot have their values changed (e.g. by proposal moves)
bool DAG::is_constant_variable(string name) {
	// If a transformation, then it must be constant (in the sense that cannot be directly changed)
	map< string, Transformation* >::iterator it = _transformation_index.find(name);
	if(it!=_transformation_index.end()) return true;
	
	RandomVariable* var = get_random_variable(name);
	map< RandomVariable*, bool >::iterator icst = _random_variable_is_constant.find(var);
	if(icst==_random_variable_is_constant.end()) error("DAG::is_constant_variable(): could not find variable");
	return icst->second;
}

void DAG::connect_graph() {
	_valid = false;
	// Connect random variables to their parents
	multimap< string, int >::iterator i;
	for(i=_parent_of_random_variable_index.begin();i!=_parent_of_random_variable_index.end();i++) {
		string var_name = i->first;
		RandomVariable* var = get_random_variable(var_name);
		const int ix = i->second;
		string dist_name = _parent_of_random_variable_distribution_name[ix];
		Distribution* dist = get_distribution(dist_name);
		string parent = _parent_of_random_variable_parent_name[ix];
		var->set_parent(parent,dist);
		dist->add_random_variable(var);
	}
	// Connect transformations to their parameters
	multimap< string, int >::iterator j;
	for(j=_parent_of_transformation_index.begin();j!=_parent_of_transformation_index.end();j++) {
		string trans_name = j->first;
		Transformation* trans = get_transformation(trans_name);
		const int ix = j->second;
		string var_name = _parent_of_transformation_variable_name[ix];
		Variable* var = get_variable(var_name);
		string param = _parent_of_transformation_parameter_name[ix];
		trans->set_parameter(param,var);
		var->add_child_transformation(trans);
	}
	// Connect distributions to their parameters
	multimap< string, int >::iterator k;
	for(k=_parent_of_distribution_index.begin();k!=_parent_of_distribution_index.end();k++) {
		string dist_name = k->first;
		Distribution* dist = get_distribution(dist_name);
		const int ix = k->second;
		string var_name = _parent_of_distribution_variable_name[ix];
		Variable* var = get_variable(var_name);
		string param = _parent_of_distribution_parameter_name[ix];
		dist->set_parameter(param,var);
		var->add_child_distribution(dist);
	}
	// Connect compound distributions to their parents
	multimap< string, int >::iterator l;
	for(l=_parent_of_compound_distribution_index.begin();l!=_parent_of_compound_distribution_index.end();l++) {
		string child_name = l->first;
		CompoundDistribution* child = dynamic_cast<CompoundDistribution*>(get_distribution(child_name));
		if(!child) error("DAG::connect_graph(): problem dynamically casting CompoundDistribution");
		const int ix = l->second;
		string parent_name = _parent_of_compound_distribution_distribution_name[ix];
		Distribution* parent = get_distribution(parent_name);
		string dist_id = _parent_of_compound_distribution_parent_name[ix];
		child->set_parent(dist_id,parent);
		parent->add_random_variable((RandomVariable*)child);
	}
}

void DAG::check_validity() {
	set< RandomVariable* >::iterator i;
	for(i=_random_variable.begin();i!=_random_variable.end();i++) {
		(*i)->assert_validity();
	}
	set< Transformation* >::iterator j;
	for(j=_transformation.begin();j!=_transformation.end();j++) {
		(*j)->assert_validity();
	}
	set< Distribution* >::iterator k;
	for(k=_distribution.begin();k!=_distribution.end();k++) {
		(*k)->assert_validity();
	}
	_valid = true;
}

bool DAG::is_valid() {
	if(false) check_validity();
	return _valid;
}

mydouble DAG::likelihood() {
	// Update dependent variables prior to calculating the likelihood
	set< Transformation* >::iterator g;
	for(g=_transformation.begin();g!=_transformation.end();g++) {
		(*g)->recalculate();
	}
	set< Distribution* >::iterator h;
	for(h=_distribution.begin();h!=_distribution.end();h++) {
		(*h)->recalculate();
	}
	// Calculate the joint probability mass/density of the variables
	_last_likelihood = mydouble(1.0);
	set< RandomVariable* >::iterator i;
	for(i=_random_variable.begin();i!=_random_variable.end();i++) {
		_last_likelihood *= (*i)->likelihood();
		if(_last_likelihood.iszero() && _attempt_all_likelihoods==false) break;
	}
	return _last_likelihood;
}

double DAG::log_likelihood() {
	// Calculate the log joint probability mass/density of the variables
	return likelihood().LOG();
}

mydouble DAG::last_likelihood() {
	return _last_likelihood;
}

void DAG::set_inference_technique(InferenceTechnique* inference_technique) {
	_inference_technique = inference_technique;
}

InferenceTechnique* DAG::get_inference_technique() {
	return _inference_technique;
}

void DAG::perform_inference() {
	if(_inference_technique==0) error("DAG::perform_inference(): inference technique not specified");
	_inference_technique->perform_inference();
}

InferenceTechnique::InferenceTechnique() {
}

InferenceTechnique::~InferenceTechnique() {
}

/*void DAG::check_casts() {
check_casts_start:
	set< Distribution* >::iterator k;
	for(k=_distribution.begin();k!=_distribution.end();k++) {
		Distribution* recast = dynamic_cast<Distribution*>(*k);
		if(recast==0) error("DAG::check_casts(): recast failed");
		if(recast!=(*k)) {
			_distribution.erase(*k);
			_distribution.insert(recast);
			goto check_casts_start;
		}
	}
}*/

void DAG::ready() {
	set< RandomVariable* >::iterator it;
	for(it=_random_variable.begin();it!=_random_variable.end();it++) {
		(*it)->receive_signal_from_parent(0,Variable::_ACCEPT);
	}
}

void DAG::reset_all() {
	set< Distribution* >::iterator it;
	for(it=_distribution.begin();it!=_distribution.end();it++) {
		(*it)->receive_signal_from_parent(0,Variable::_SET);
	}
	set< Transformation* >::iterator jt;
	for(jt=_transformation.begin();jt!=_transformation.end();jt++) {
		(*jt)->receive_signal_from_parent(0,Variable::_SET);
	}
}

void DAG::set_attempt_all_likelihoods(const bool attempt_all_likelihoods) {
	_attempt_all_likelihoods = attempt_all_likelihoods;
}
	
} // namespace gcat
