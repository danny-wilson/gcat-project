/*  Copyright 2012 Daniel Wilson.
 *
 *  DependentVariable.h
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
#ifndef _DEPENDENT_VARIABLE_H_
#define _DEPENDENT_VARIABLE_H_
#include <DAG/Component.h>
#include <DAG/Value.h>
#include <vector>
#include <map>
#include <string>

using std::string;
using std::vector;
using std::map;
using std::multimap;

namespace gcat {

class DependentVariable : public virtual DAGcomponent {
protected:
	// Flag indicates whether recalculation is necessary
	mutable bool _recalculate;

private:
	//DependencySignal _next_action;
	
	// Number of parameters
	int _np;
	// Vector of pointers to parameters, and an index of those parameters
	vector< Value* > _parameter;
	multimap< Value* , int > _parameter_index;
	// Vector of parameter names, and an index of those parameter names
	vector< string > _parameter_name;
	map< string, int > _parameter_name_index;

public:
	// Constructor
	DependentVariable(const string* parameter_name=0, const int n_parameters=0);
	// Copy constructor
	DependentVariable(const DependentVariable &x);
	// Destructor
	virtual ~DependentVariable();
	
	// Number of parameters
	int n_parameters() const;
	// Returns the parameter number of a parameter, or -1 if not found
	int parameter_number(string parameter_name) const;
	// Returns the parameter name of a numbered parameter
	string parameter_name(int parameter_number) const;
	// Check the named parameter has the right derived type of Variable
	bool check_parameter_type(string parameter_name, Variable* parameter);
	// Check the numbered parameter has the right derived type of Variable. This function must be implemented in the derived class.
	virtual bool check_parameter_type(const int i, Variable* parameter) = 0;
	// Clear the named parameter
	void clear_parameter(string parameter_name);
	// Clear the numbered parameter
	void clear_parameter(const int i);
	// Sets a named parameter using Variable* and dynamic type checking
	void set_parameter(string parameter_name, Variable* parameter);
	// Sets a numbered parameter using Variable* and dynamic type checking
	void set_parameter(const int i, Variable* parameter);
	// Returns an immutable pointer to a named parameter
	Value const* get_parameter(string parameter_name) const;
	// Returns an immutable pointer to a numbered parameter
	Value const* get_parameter(const int i) const;
	// Returns a pointer to a named parameter
	Value* get_parameter(string parameter_name);
	// Returns a pointer to a numbered parameter
	Value* get_parameter(const int i);
	// Is the variable an orphan (i.e. has no parent distribution set)?
	bool is_orphan() const;
	
	// Receive update signals from parameter variables
	virtual void receive_signal_from_parent(const Value* v, const Variable::Signal sgl) = 0;
	
	// Important: recalculate is now an inherited function that DAG guarantees to call each iteration.
	// However, it does not guarantee to call it before another object calls a value function, e.g.
	// get_double(). Therefore, if recalculate() does anything, there must be a mechanism to check
	// that the recalculation has been performed before returning value functions.
	//
	// The rationale is as follows. Imagine y1 and y2 are transformations of x1 and x2, and m indicates
	// whether a distribution uses parameter y1 or y2 on a given iteration. If m==1 and x2 is updated,
	// then y2 may not be updated if the code relies on a value function call. The next time y2 is queried, 
	// (e.g. if m==2) this could lead to a bug.
	//
	// Another thing: the purpose of recalculate is efficiency. Whether it is used or not shouldn't
	// affect the apparent behaviour of the object. Therefore it is const and variables which are
	// modified by recalculate must be declared mutable, including the _recalculate flag itself.
	virtual void recalculate() const;
	
protected:
	// Validate
	virtual string validate() const;
};
	
} // namespace gcat

#endif // _DEPENDENT_VARIABLE_H_
