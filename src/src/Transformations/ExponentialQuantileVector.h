/*  Copyright 2012 Daniel Wilson.
 *
 *  ExponentialQuantileVector.h
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
#ifndef _EXPONENTIAL_QUANTILE_VECTOR_TRANSFORM_H_
#define _EXPONENTIAL_QUANTILE_VECTOR_TRANSFORM_H_
#include <Variables/Continuous.h>
#include <Variables/ContinuousVector.h>
#include <DAG/Transformation.h>

namespace gcat {

class ExponentialQuantileVectorTransform : public ContinuousVectorVariable, public Transformation {
private:
	int _n;
	mutable bool _lambda_changed, _quantile_changed;
	mutable vector<double> _x, _x_prev;
	mutable vector<bool> _bad, _bad_prev;
	vector<bool> _has_changed;
public:
	// Constructor
	ExponentialQuantileVectorTransform(const int n, string name="", DAG* dag=0);
	// Copy constructor
	ExponentialQuantileVectorTransform(const ExponentialQuantileVectorTransform& x);
	
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
	
	// Convenience functions
	void set_lambda(ContinuousVariable* mean);
	void set_quantile(ContinuousVectorVariable* quantile);
	ContinuousVariable const* get_lambda() const;	
	ContinuousVectorVariable const* get_quantile() const;
	
	// Overload method inherited from Transformation
	void receive_signal_from_parent(const Value* v, const Variable::Signal sgl);
	void recalculate() const;
	
};
	
} // namespace gcat

#endif // _EXPONENTIAL_QUANTILE_VECTOR_TRANSFORM_H_




