/*  Copyright 2012 Daniel Wilson.
 *
 *  PowerTransform.cpp
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
#include <Transformations/PowerTransform.h>

namespace gcat {

const string PowerTransformParameterNames[2] = {"base","exponent"};

PowerTransform::PowerTransform(string name, DAG* dag) : DAGcomponent(name,dag,"PowerTransform"), Transformation(PowerTransformParameterNames,2) {
}

PowerTransform::PowerTransform(const PowerTransform& x) : DAGcomponent(x), Transformation(x) {
}

double PowerTransform::get_double() const {
	double x = get_base()->get_double();
	double y = get_exponent()->get_double();
	return pow(x,y);
}

bool PowerTransform::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		case 0:	// base
			return(dynamic_cast<ContinuousVariable*>(parameter));
		case 1:	// exponent
			return(dynamic_cast<ContinuousVariable*>(parameter));
		default:
			error("PowerTransform::check_parameter_type(): parameter not found");
	}
	return false;
}

void PowerTransform::set_base(ContinuousVariable* x) {
	set_parameter(0,(Variable*)x);
}

void PowerTransform::set_exponent(ContinuousVariable* x) {
	set_parameter(1,(Variable*)x);
}

ContinuousVariable const* PowerTransform::get_base() const {
	return (ContinuousVariable const*)get_parameter(0);
}

ContinuousVariable const* PowerTransform::get_exponent() const {
	return (ContinuousVariable const*)get_parameter(1);
}
	
} // namespace gcat

