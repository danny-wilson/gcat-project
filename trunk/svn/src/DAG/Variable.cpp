/*  Copyright 2012 Daniel Wilson.
 *
 *  Variable.cpp
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
#include <DAG/Variable.h>
#include <DAG/Transformation.h>
#include <DAG/Distribution.h>
#include <myerror.h>

namespace gcat {

// NB:- Variable is abstract and inherits virtually from DAGcomponent, so any call to DAGcomponent ctor would be ignored
Variable::Variable() : _thisValue(0) {
}

Variable::Variable(const Variable &var) : _child_distribution(var._child_distribution), _child_transformation(var._child_transformation), _thisValue(0) {
}

Variable::~Variable() {};

void Variable::add_child_distribution(Distribution* child) {
	if(child==0) error("Variable::add_child_distribution(): Attempting to assign null pointer");
	_child_distribution.insert(child);
}

void Variable::remove_child_distribution(Distribution* child) {
	if(child==0) error("Variable::remove_child_distribution(): Attempting to remove null pointer");
	multiset< Distribution* >::iterator it = _child_distribution.find(child);
	if(it==_child_distribution.end()) error("Variable::remove_child_distribution(): Distribution is not a child");
	_child_distribution.erase(it);
}

int Variable::n_child_distributions() const {
	return _child_distribution.size();
}

void Variable::add_child_transformation(Transformation* child) {
	if(child==0) error("Variable::add_child_transformation(): Attempting to assign null pointer");
	_child_transformation.insert(child);
}

void Variable::remove_child_transformation(Transformation* child) {
	if(child==0) error("Variable::remove_child_transformation(): Attempting to remove null pointer");
	multiset< Transformation* >::iterator it = _child_transformation.find(child);
	if(it==_child_transformation.end()) error("Variable::remove_child_transformation(): Transformation is not a child");
	_child_transformation.erase(it);
}

int Variable::n_child_transformations() const {
	return _child_transformation.size();
}

string Variable::validate() const {
	return DAGcomponent::validate();
}

// Signalling functions: NB:- functions in derived classes must call these functions in the base class
void Variable::send_signal_to_children(const Signal sgl) {
	// Signal to each daughter Distribution and parent that the value has changed
	multiset< Distribution* >::iterator it;
	for(it=_child_distribution.begin();it!=_child_distribution.end();it++) {
		(*it)->receive_signal_from_parent(to_Value(),sgl);
	}
	// Signal to each daughter Transformation and parent that the value has changed
	multiset< Transformation* >::iterator jt;
	for(jt=_child_transformation.begin();jt!=_child_transformation.end();jt++) {
		(*jt)->receive_signal_from_parent(to_Value(),sgl);
	}
}

const Value* Variable::to_Value() const {
//	Definitely doesn't work!!!!:
//	static const Value* _thisValue(dynamic_cast<const Value*>(this));
//	if(_thisValue==0) error("Variable::to_Value(): could not dynamic cast");
	if(_thisValue==0) _thisValue = dynamic_cast<Value*>(const_cast<Variable*>(this));
	return _thisValue;
}
	
} // namespace gcat
