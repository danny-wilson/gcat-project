/*  Copyright 2012 Daniel Wilson.
 *
 *  AbsoluteTransform.cpp
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
#include <Transformations/AbsoluteTransform.h>

namespace gcat {

const string AbsoluteTransformParameterNames[1] = {"x"};

AbsoluteTransform::AbsoluteTransform(string name, DAG* dag) : DAGcomponent(name,dag,"AbsoluteTransform"), Transformation(AbsoluteTransformParameterNames,1) {
}

AbsoluteTransform::AbsoluteTransform(const AbsoluteTransform& x) : DAGcomponent(x), Transformation(x) {
}

double AbsoluteTransform::get_double() const {
	return fabs(get_x()->get_double());
}

bool AbsoluteTransform::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		case 0:	// x
			return(dynamic_cast<ContinuousVariable*>(parameter));
		default:
			error("AbsoluteTransform::check_parameter_type(): parameter not found");
	}
	return false;
}

void AbsoluteTransform::set_x(ContinuousVariable* x) {
	set_parameter(0,(Variable*)x);
}

ContinuousVariable const* AbsoluteTransform::get_x() const {
	return (ContinuousVariable const*)get_parameter(0);
}
	
} // namespace gcat

