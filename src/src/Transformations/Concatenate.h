/*  Copyright 2012 Daniel Wilson.
 *
 *  Concatenate.h
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
#ifndef _CONCATENATE_TRANSFORM_H_
#define _CONCATENATE_TRANSFORM_H_
#include <Variables/Continuous.h>
#include <Variables/ContinuousVector.h>
#include <DAG/Transformation.h>

namespace gcat {

class ConcatenateTransform : public ContinuousVectorVariable, public Transformation {
private:
	// Number of items to concatenate
	int _n;
	// Combined length of concatenated items
	mutable int _L;
	// Cumulative length of the items
	mutable vector<int> _cum_L;
	// Indicate whether item is a scalar or vector
	mutable vector<bool> _is_scalar;
	// Initialized?
	mutable bool _init;
	// Recalculate?
	mutable bool _recalculate;
	// Internal copy of concatenated items
	mutable vector<double> _x, _x_prev;
	// Keep track of whether elements have changed
	mutable vector<bool> _has_changed;
public:
	// Constructor
	ConcatenateTransform(const int n, const int L, string name="", DAG* dag=0);
	// Copy constructor
	ConcatenateTransform(const ConcatenateTransform& x);
	
	// Implementation of virtual functions inherited from base classes
	// Get length of the variable
	int length() const;
	// Get value at position i
	double get_double(const int i) const;
	// Get vector of values
	vector<double> get_doubles() const;
	// Has the value changed at position i?
	bool has_changed(const int i) const;
	// Has the value changed at each position?
	vector<bool> has_changed() const;
	// Type-checking for parameter(s)
	bool check_parameter_type(const int i, Variable* parameter);
	
	// Overload method inherited from Transformation
	void receive_signal_from_parent(const Value* v, const Variable::Signal sgl);
	
private:
	// Private functions
	void recalculate() const;
	void initialize() const;
};
	
} // namespace gcat

#endif // _CONCATENATE_TRANSFORM_H_
