/*  Copyright 2012 Daniel Wilson.
 *
 *  Continuous2ContinuousMosaic.h
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
#ifndef _CONTINUOUS_VARIABLE_2_CONTINUOUS_MOSAIC_VARIABLE_H_
#define _CONTINUOUS_VARIABLE_2_CONTINUOUS_MOSAIC_VARIABLE_H_
#include <Variables/Continuous.h>
#include <Variables/ContinuousMosaic.h>
#include <DAG/Transformation.h>

namespace gcat {

const string ContinuousVariable2ContinuousMosaicVariableParameterNames[1] = {"x"};

class ContinuousVariable2ContinuousMosaicVariable : public ContinuousMosaicVariable, public Transformation {
private:
	int _n;
public:
	// Constructor
	ContinuousVariable2ContinuousMosaicVariable(string name="", DAG* dag=0, const int n=1) : DAGcomponent(name,dag,"ContinuousVariable2ContinuousMosaicVariable"), Transformation(ContinuousVariable2ContinuousMosaicVariableParameterNames,1), _n(n) {};
	// Copy constructor
	ContinuousVariable2ContinuousMosaicVariable(const ContinuousVariable2ContinuousMosaicVariable& x) : DAGcomponent(x), Transformation(x), _n(x._n) {};
	
	// Implementation of virtual functions inherited from ContinuousVector
	// Get length of the variable
	int length() const {
		return _n;
	}
	// Get value at position i
	double get_double(const int i) const {
		if(i<0 || i>=_n) error("ContinuousVariable2ContinuousMosaicVariable::get_double(i) index out of range");
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
	
	// Implementation of virtual functions inherited from ContinuousMosaic
	int nblocks() const {
		return 1;
	}
	// Is there a left breakpoint at position i?
	bool is_block_start(const int i) const {
		return (i==0);
	}
	// Is there a right breakpoint at position i?
	bool is_block_end(const int i) const {
		return (i==_n-1);
	}
	// Where is the start of the current block?
	int block_start(const int i) const {
		return 0;
	}
	// Where is the end of the current block?
	int block_end(const int i) const {
		return _n-1;
	}
	
	bool check_parameter_type(const int i, Variable* parameter)  {
		switch(i) {
			case 0:	// x
				return(dynamic_cast<ContinuousVariable*>(parameter));
			default:
				error("ContinuousVariable2ContinuousMosaicVariable::check_parameter_type(): parameter not found");
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

#endif // _CONTINUOUS_VARIABLE_2_CONTINUOUS_MOSAIC_VARIABLE_H_

