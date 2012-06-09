/*  Copyright 2012 Daniel Wilson.
 *
 *  Distribution.cpp
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
#include <DAG/Distribution.h>
#include <DAG/RandomVariable.h>
#include <DAG/CompoundDistribution.h>
#include <DAG/DAG.h>
#include <myerror.h>

namespace gcat {

Distribution::Distribution(const string* parameter_name, const int n_parameters, const bool add_to_DAG) : DependentVariable(parameter_name,n_parameters), _likelihood(0), _previous_likelihood(0) {
	if(getDAG()!=0 && add_to_DAG==true) getDAG()->add_distribution(this);
}

Distribution::Distribution(const Distribution &x) : DependentVariable((const DependentVariable &)x), 
	_likelihood(x._likelihood), _previous_likelihood(x._previous_likelihood), _random_variable(x._random_variable) {
}

Distribution::~Distribution() {};

void Distribution::add_random_variable(RandomVariable* random_variable) {
	if(random_variable==0) error("Distribution::add_random_variable(): Attempting to assign null variable");
	if(!check_random_variable_type(random_variable)) {
		string errTxt = "Distribution::add_random_variable(): variable " + random_variable->name() + " of wrong type for distribution " + name();
		error(errTxt.c_str());
	}
	// If the former worked, this should work
	if(!random_variable->to_Value()) error("Distribution::add_random_variable(): could not cast to Value type");
	set< RandomVariable* >::iterator it = _random_variable.find(random_variable);
	if(it!=_random_variable.end()) error("Distribution::add_random_variable(): Variable already added");
	_random_variable.insert(random_variable);
}

void Distribution::remove_random_variable(RandomVariable* random_variable) {
	if(random_variable==0) error("Distribution::remove_random_variable(): Attempting to remove null variable");
	set< RandomVariable* >::iterator it = _random_variable.find(random_variable);
	if(it==_random_variable.end()) error("Distribution::remove_random_variable(): Variable not found");
	_random_variable.erase(it);
}

int Distribution::n_random_variables() const {
	return _random_variable.size();
}

// Signalling function: can be over-written in derived classes
void Distribution::receive_signal_from_parent(const Value* v, const Variable::Signal sgl) {
	propagate_signal_to_children(sgl);
}

void Distribution::propagate_signal_to_children(const Variable::Signal sgl) {
	set< RandomVariable* >::iterator i;
	for(i=_random_variable.begin();i!=_random_variable.end();i++) {
		(*i)->receive_signal_from_parent(this,sgl);
	}
}

string Distribution::validate() const {
	// Warn if no random variables
	if(n_random_variables()==0) {
		string wrnMsg = "Distribution ";
		wrnMsg += name();
		wrnMsg += " of type ";
		wrnMsg += type();
		wrnMsg += " has no random variables";
		myutils::warning(wrnMsg.c_str());
	}
	return DependentVariable::validate();
}

set< RandomVariable* >& Distribution::random_variable() {
	return _random_variable;
}

} // namespace gcat
