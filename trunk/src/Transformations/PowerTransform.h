/*  Copyright 2012 Daniel Wilson.
 *
 *  PowerTransform.h
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
#ifndef _POWER_TRANSFORM_H_
#define _POWER_TRANSFORM_H_
#include <DAG/Transformation.h>
#include <Variables/Continuous.h>

namespace gcat {

class PowerTransform : public ContinuousVariable, public Transformation {
public:
	// Constructor
	PowerTransform(string name="", DAG* dag=0);
	// Copy constructor
	PowerTransform(const PowerTransform& x);
	
	// Implementation of virtual functions inherited from base classes
	double get_double() const;
	bool check_parameter_type(const int i, Variable* parameter);
	
	// Convenience functions
	void set_base(ContinuousVariable* base);
	void set_exponent(ContinuousVariable* exponent);
	ContinuousVariable const* get_base() const;
	ContinuousVariable const* get_exponent() const;
};
	
} // namespace gcat

#endif //  _POWER_TRANSFORM_H_


