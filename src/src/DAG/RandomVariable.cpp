/*  Copyright 2012 Daniel Wilson.
 *
 *  RandomVariable.cpp
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
#include <DAG/RandomVariable.h>
#include <DAG/DAG.h>
#include <DAG/Distribution.h>
#include <DAG/Value.h>

namespace gcat {

const string RandomVariableDistributionName[1] = {"distribution"};

// As for the Variable <-> DAGcomponent relationship, RandomVariable is abstract and inherits DAGcomponent and Variable virtually so even
// if Variable takes constructor arguments, they would always be ignored, and can use default DAGcomponent ctor arguments for same reason
RandomVariable::RandomVariable(const string* parent_name, const int n_parents, const bool add_to_DAG) : _calculate_likelihood(true), _likelihood(0), _previous_likelihood(0), _np(n_parents) {
	_parent_name = vector<string>(_np);
	int i;
	for(i=0;i<_np;i++) _parent_name[i] = parent_name[i];
	// Initialize the size of the parent distribution vector
	_parent = vector< Distribution* >(_np,(Distribution*)0);
	// Initialize the mapping of names to positions in the vector
	for(i=0;i<_np;i++) {
		_parent_name_index[parent_name[i]] = i;
	}
	if(getDAG()!=0 && add_to_DAG==true) getDAG()->add_random_variable(this);
	rvname = name();
}

RandomVariable::RandomVariable(const RandomVariable &var) : _calculate_likelihood(var._calculate_likelihood), _likelihood(var._likelihood), _previous_likelihood(var._previous_likelihood),
_np(var._np), _parent(var._parent), _parent_index(var._parent_index), _parent_name(var._parent_name), _parent_name_index(var._parent_name_index) {
}

RandomVariable::~RandomVariable() {};

double RandomVariable::log_likelihood() {
	return likelihood().LOG();
}

mydouble RandomVariable::likelihood() {
	return (_calculate_likelihood) ? calculate_likelihood() : _likelihood;
}

mydouble RandomVariable::calculate_likelihood() {
	try {
		_likelihood = (_parent[0]==0) ? mydouble(1) : _parent[0]->likelihood(this,to_Value());
		int i;
		for(i=1;i<_np;i++) {
			if(_parent[i]!=0) _likelihood *= _parent[i]->likelihood(this,to_Value());
		}
		if(_likelihood.isinfinity()) {
			throw BadValueException(to_Value(),"RandomVariable::calculate_likelihood(): Infinite likelihood");
		}
		if(_likelihood.isbad()) {
			throw BadValueException(to_Value(),"RandomVariable::calculate_likelihood(): Bad likelihood");
		}
	}
	// Default behaviour for catching bad value exceptions thrown by objects derived from Value.
	// This means that implementations of Distribution::likelihood() don't need explicit code to
	// catch exceptions thrown on calls to, e.g. parameter->get_double(). However, the likelihood
	// function itself might throw a BadValueException if the value (which is good) is outside
	// a range. However, in that case it would be better simply to return mydouble(0).
	//
	// Implementations of Distribution::likelihood() should also be robust to premature function exits
	// caused by exceptions thrown during calls to derived Value object member functions. One way
	// to build in such robustness manually is to catch the error inside Distribution::likelihood(),
	// do the necessary processing, then re-throw the exception for catching here.
	catch (BadValueException &e) {
		_likelihood = mydouble(0);
	}
	_calculate_likelihood = false;
//	cout << "RV = " << name() << " loglik = " << _likelihood.LOG() << endl;
	return _likelihood;
}

mydouble RandomVariable::stored_likelihood() const {
	return _likelihood;
}

int RandomVariable::n_parents() const {
	return _np;
}

int RandomVariable::parent_number(string parent_name) const {
	map< string, int >::const_iterator it = _parent_name_index.find(parent_name);
	if(it==_parent_name_index.end()) return -1;
	return it->second;
}

string RandomVariable::parent_name(int parent_number) const{
	if(parent_number<0 || parent_number>=_np) error("RandomVariable::parent_name(): number out of range");
	return _parent_name[parent_number];
}

// Clear the current incumbent of a named parameter
void RandomVariable::clear_parent(string parent_name) {
	const int i = parent_number(parent_name);
	clear_parent(i);
}

// Clear the current incumbent of a numbered parameter
void RandomVariable::clear_parent(const int i) {
	if(i<0 || i>=_np) error("RandomVariable::clear_parent(): parent not found");
	Distribution* parent = _parent[i];
	// If the parent had not yet been set, return
	if(parent==0) return;
	// Clear the parent
	_parent[i] = 0;
	// Clear the specific entry of the parent from the multimap index
	pair< multimap< Distribution*, int >::iterator, multimap< Distribution*, int >::iterator > rg = _parent_index.equal_range(parent);
	multimap< Distribution*, int >::iterator it;
	for(it=rg.first;it!=rg.second;it++) {
		if(it->second==i) {
			_parent_index.erase(it);
			break;
		}
	}
	if(it==_parent_index.end()) error("RandomVariable::clear_parent(): not found in _parent_index");
}

// Sets a named parent using RandomVariable* and dynamic type checking
void RandomVariable::set_parent(string parent_name, Distribution* parent) {
	const int i = parent_number(parent_name);
	set_parent(i,parent);
}

// Sets a numbered parent using RandomVariable* and dynamic type checking
void RandomVariable::set_parent(const int i, Distribution* parent) {
	if(parent==0) error("RandomVariable::set_parent(): Attempting to assign null distribution");
	if(i<0 || i>=_np) error("RandomVariable::set_parent(): parent not found");
	// Remove the incumbent parent
	if(get_parent(i)!=0) error("RandomVariable::set_parent(): parent already set");
	//clear_parent(i);
	// Perform dynamic type checking via a call to a virtual function implemented in the derived class
	//if(!check_parent_type(i,parent)) error("RandomVariable::set_parent(): parent of wrong type");
	// Set the parent
	_parent[i] = parent;
	// Index it
	pair< Distribution*, int > entry(parent,i);
	_parent_index.insert(entry);
	// Notify the parent
	//parent->add_daughter(this);
}

Distribution const* RandomVariable::get_parent(string parent_name) const {
	const int i = parent_number(parent_name);
	return get_parent(i);
}

Distribution const* RandomVariable::get_parent(const int i) const {
	if(i<0 || i>=_np) error("RandomVariable::get_parent(): parent not found");
	return _parent[i];
}

Distribution* RandomVariable::get_parent(string parent_name) {
	const int i = parent_number(parent_name);
	return get_parent(i);
}

Distribution* RandomVariable::get_parent(const int i) {
	if(i<0 || i>=_np) error("RandomVariable::get_parent(): parent not found");
	return _parent[i];
}

bool RandomVariable::is_orphan() const {
	int i;
	for(i=0;i<_np;i++) {
		if(_parent[i]!=0) return false;
	}
	return true;
}

void RandomVariable::receive_signal_from_parent(const Distribution* dist, const Signal sgl) {
	act_on_signal(sgl);
}
	
void RandomVariable::act_on_signal(const Signal sgl) {
	if(sgl==_SET) {
		_calculate_likelihood = true;
	}
	else if(sgl==_PROPOSE) {
		_previous_likelihood = _likelihood;
		_calculate_likelihood = true;
	}
	else if(sgl==_ACCEPT) {
		_calculate_likelihood = false;
	}
	else if(sgl==_REVERT) {
		_likelihood = _previous_likelihood;
		_calculate_likelihood = false;
	}
	else error("RandomVariable::receive_signal_from_parent(): unexpected signal");
}

string RandomVariable::validate() const {
	// Warn if no daughters or parents
	if(is_orphan() && n_child_distributions()==0 && n_child_transformations()==0) {
		string wrnMsg = "RandomVariable ";
		wrnMsg += name();
		wrnMsg += " of type ";
		wrnMsg += type();
		wrnMsg += " is stranded";
		myutils::warning(wrnMsg.c_str());
	}
	return Parameter::validate();
}
	
} // namespace gcat

