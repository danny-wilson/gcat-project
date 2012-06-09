/*  Copyright 2012 Daniel Wilson.
 *
 *  LinearMosaic.h
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
 *
 *
 *	Perform the linear transformation 
 *		x = mu + sigma*z 
 *	where x and y are ContinuousMosaicVariable objects.
 *
 *	The purpose in mind is to transform N(0,1) into N(mu,sigma).
 *
 */
#ifndef _LINEAR_MOSAIC_TRANSFORM_H_
#define _LINEAR_MOSAIC_TRANSFORM_H_
#include <Variables/Continuous.h>
#include <Variables/ContinuousMosaic.h>
#include <DAG/Transformation.h>

namespace gcat {

class LinearMosaicTransform : public ContinuousMosaicVariable, public Transformation {
private:
	int _n;
	mutable bool _mean_changed, _sd_changed, _z_changed;
	mutable vector<double> _x, _x_prev;
	mutable vector<bool> _bad, _bad_prev;
	vector<bool> _has_changed;
public:
	// Constructor
	LinearMosaicTransform(const int n, string name="", DAG* dag=0);
	// Copy constructor
	LinearMosaicTransform(const LinearMosaicTransform& x);
	
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
	// Get the number of breakpoints
	int nblocks() const;
	// Is there a left breakpoint at position i?
	bool is_block_start(const int i) const;
	// Is there a right breakpoint at position i?
	bool is_block_end(const int i) const;
	// Where is the start of the current block?
	int block_start(const int i) const;
	// Where is the end of the current block?
	int block_end(const int i) const;
	// Type-checking for parameter(s)
	bool check_parameter_type(const int i, Variable* parameter);
	
	// Convenience functions
	void set_mean(ContinuousVariable* mean);
	void set_sd(ContinuousVariable* sd);
	void set_z(ContinuousMosaicVariable* z);
	ContinuousVariable const* get_mean() const;	
	ContinuousVariable const* get_sd() const;	
	ContinuousMosaicVariable const* get_z() const;
	
	// Overload method inherited from Transformation
	void receive_signal_from_parent(const Value* v, const Variable::Signal sgl);
	void recalculate() const;
};
	
} // namespace gcat

#endif // _LINEAR_MOSAIC_TRANSFORM_H_

