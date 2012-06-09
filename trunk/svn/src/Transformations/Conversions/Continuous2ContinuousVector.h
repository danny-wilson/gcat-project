/*  Copyright 2012 Daniel Wilson.
 *
 *  Continuous2ContinuousVector.h
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
#ifndef _CONTINUOUS_VARIABLE_2_CONTINUOUS_VECTOR_VARIABLE_H_
#define _CONTINUOUS_VARIABLE_2_CONTINUOUS_VECTOR_VARIABLE_H_
#include <Variables/Continuous.h>
#include <Variables/ContinuousVector.h>
#include <DAG/Transformation.h>

namespace gcat {

const string ContinuousVariable2ContinuousVectorVariableParameterNames[1] = {"x"};

class ContinuousVariable2ContinuousVectorVariable : public ContinuousVectorVariable, public Transformation {
private:
	int _n;		// Length of vector
public:
	// Constructor
	ContinuousVariable2ContinuousVectorVariable(string name="", DAG* dag=0, const int n=1) : DAGcomponent(name,dag,"ContinuousVariable2ContinuousVectorVariable"), Transformation(ContinuousVariable2ContinuousVectorVariableParameterNames,1), _n(1) {};
	// Copy constructor
	ContinuousVariable2ContinuousVectorVariable(const ContinuousVariable2ContinuousVectorVariable& x) : DAGcomponent(x), Transformation(x), _n(x._n) {};
	
	// Implementation of virtual functions inherited from ContinuousVector
	// Get length of the variable
	int length() const {
		return _n;
	}
	// Get value at position i
	double get_double(const int i) const {
		if(i<0 || i>=_n) error("ContinuousVariable2ContinuousVectorVariable::get_double(i) index out of range");
		return get_x()->get_double();
	}
	// Get vector of values
	vector<double> get_doubles() const {
		return vector<double>(_n,get_x()->get_double());
	}
	// Has the value changed at position i?
	bool has_changed(const int i) const {
		return true;	// Inefficient!
	}
	// Has the value changed at each position?
	vector<bool> has_changed() const {
		return vector<bool>(_n,true);	// Inefficient!
	}	
	
	bool check_parameter_type(const int i, Variable* parameter)  {
		switch(i) {
			case 0:	// x
				return(dynamic_cast<ContinuousVariable*>(parameter));
			default:
				error("ContinuousVariable2ContinuousVectorVariable::check_parameter_type(): parameter not found");
		}
		return false;
	}
	
	// Convenience functions
	void set_x(ContinuousVariable* x) {
		set_parameter(0,(Variable*)x);
	}
	ContinuousVariable const* get_x() const {
		return (ContinuousVariable const*)get_parameter(0);
	}
};
	
} // namespace gcat

#endif // _CONTINUOUS_VARIABLE_2_CONTINUOUS_VECTOR_VARIABLE_H_


