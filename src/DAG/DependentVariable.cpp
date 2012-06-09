/*  Copyright 2012 Daniel Wilson.
 *
 *  DependentVariable.cpp
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
#include <DAG/DependentVariable.h>
#include <DAG/Variable.h>
#include <DAG/Parameter.h>
#include <DAG/DAG.h>
#include <myerror.h>

namespace gcat {

DependentVariable::DependentVariable(const string* parameter_name, const int n_parameters) : _np(n_parameters), _recalculate(true) {
	_parameter_name = vector<string>(_np);
	int i;
	for(i=0;i<_np;i++) _parameter_name[i] = parameter_name[i];
	// Initialize the size of the parameter vector
	_parameter = vector< Value* >(_np,(Value*)0);
	// Initialize the mapping of names to positions in the vector
	for(i=0;i<_np;i++) {
		_parameter_name_index[parameter_name[i]] = i;
	}
}

DependentVariable::DependentVariable(const DependentVariable &x) : /*DAGcomponent((const DAGcomponent &)x),*/ /*_next_action(x._next_action),*/
_np(x._np), _parameter(x._parameter), _parameter_index(x._parameter_index),
_parameter_name(x._parameter_name), _parameter_name_index(x._parameter_name_index),
_recalculate(x._recalculate) {
}

DependentVariable::~DependentVariable() {};

int DependentVariable::n_parameters() const {
	return _np;
}

int DependentVariable::parameter_number(string parameter_name) const {
//	cout << "DependentVariable " << name() << " has parameters";
//	map< string, int >::const_iterator it;
//	for(it=_parameter_name_index.begin();it!=_parameter_name_index.end();it++) cout << " " << it->first;
//	cout << endl;
//	it = _parameter_name_index.find(parameter_name);
	map< string, int >::const_iterator it = _parameter_name_index.find(parameter_name);
	if(it==_parameter_name_index.end()) return -1;
	return it->second;
}

string DependentVariable::parameter_name(int parameter_number) const{
	if(parameter_number<0 || parameter_number>=_np) error("DependentVariable::parameter_name(): number out of range");
	return _parameter_name[parameter_number];
}

bool DependentVariable::check_parameter_type(string parameter_name, Variable *parameter) {
	const int i = parameter_number(parameter_name);
	// Call the virtual function which must be implemented in the derived class
	return check_parameter_type(i,parameter);
}

// Clear the current incumbent of a named parameter
void DependentVariable::clear_parameter(string parameter_name) {
	const int i = parameter_number(parameter_name);
	clear_parameter(i);
}

// Clear the current incumbent of a numbered parameter
void DependentVariable::clear_parameter(const int i) {
	if(i<0 || i>=_np) error("DependentVariable::clear_parameter(): parameter not found");
	Value* parameter = _parameter[i];
	// If the parameter had not yet been set, return
	if(parameter==0) return;
	// Clear the parameter
	_parameter[i] = 0;
	// Clear the specific entry of the parameter from the multimap index
	pair< multimap< Value*, int >::iterator, multimap< Value*, int >::iterator > rg = _parameter_index.equal_range(parameter);
	multimap< Value*, int >::iterator it;
	for(it=rg.first;it!=rg.second;it++) {
		if(it->second==i) {
			_parameter_index.erase(it);
			break;
		}
	}
	if(it==_parameter_index.end()) error("DependentVariable::clear_parameter(): not found in _parameter_index");
	// Notify the parameter
	//parameter->remove_daughter(this);
}

// Sets a named parameter using Variable* and dynamic type checking
void DependentVariable::set_parameter(string parameter_name, Variable* parameter) {
	const int i = parameter_number(parameter_name);
	if(i==-1) {
		string errMsg = "DependentVariable::set_parameter: object \"";
		errMsg += name();
		errMsg += "\" does not have parameter \"";
		errMsg += parameter_name;
		errMsg += "\"";
		error(errMsg.c_str());
	}
	set_parameter(i,parameter);
}

// Sets a numbered parameter using Variable* and dynamic type checking
void DependentVariable::set_parameter(const int i, Variable* variable) {
	if(variable==0) error("DependentVariable::set_parameter(): Attempting to assign null variable");
	if(i<0 || i>=_np) error("DependentVariable::set_parameter(): parameter not found");
	// Remove the incumbent parameter
	if(get_parameter(i)!=0) error("DependentVariable::set_parameter(): parameter already set");
	//clear_parameter(i);
	// Perform dynamic type checking via a call to a virtual function implemented in the derived class
	if(!check_parameter_type(i,variable)) {
		string errTxt = "DependentVariable::set_parameter(): variable " + variable->name() + " of wrong type for " + name();
		error(errTxt.c_str());
	}
	// Convert from Variable* to Value*. This one dynamic_cast faciliates rapid static casts later
	Value* parameter = dynamic_cast<Value*>(variable);
	// Set the parameter
	_parameter[i] = parameter;
	// Index it
	pair< Value*, int > entry(parameter,i);
	_parameter_index.insert(entry);
	// Notify the parameter
	//parameter->add_daughter(this);
}

Value const* DependentVariable::get_parameter(string parameter_name) const {
	const int i = parameter_number(parameter_name);
	return get_parameter(i);
}

Value const* DependentVariable::get_parameter(const int i) const {
	if(i<0 || i>=_np) error("DependentVariable::get_parameter(): parameter not found");
	return _parameter[i];
}

Value* DependentVariable::get_parameter(string parameter_name) {
	const int i = parameter_number(parameter_name);
	return get_parameter(i);
}

Value* DependentVariable::get_parameter(const int i) {
	if(i<0 || i>=_np) error("DependentVariable::get_parameter(): parameter not found");
	return _parameter[i];
}

bool DependentVariable::is_orphan() const {
	int i;
	for(i=0;i<_np;i++) {
		if(_parameter[i]!=0) return false;
	}
	return true;
}

string DependentVariable::validate() const {
	// Error if unset parameters
	int k;
	for(k=0;k<n_parameters();k++) {
		if(get_parameter(k)==0) {
			string errMsg = "Parameter ";
			errMsg += parameter_name(k);
			errMsg += " for distribution ";
			errMsg += name();
			errMsg += " of type ";
			errMsg += type();
			errMsg += " not set";
			return errMsg;
		}
	}
	return DAGcomponent::validate();
}

void DependentVariable::recalculate() const {
	_recalculate = false;
}
	
} // namespace gcat
