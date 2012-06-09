/*  Copyright 2012 Daniel Wilson.
 *
 *  InverseLogitTransform.cpp
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
#include <Transformations/InverseLogitTransform.h>

namespace gcat {

const string InverseLogitTransformParameterNames[1] = {"p"};

InverseLogitTransform::InverseLogitTransform(string name, DAG* dag) : DAGcomponent(name,dag,"InverseLogitTransform"), Transformation(InverseLogitTransformParameterNames,1) {
}

InverseLogitTransform::InverseLogitTransform(const InverseLogitTransform& x) : DAGcomponent(x), Transformation(x) {
}

double InverseLogitTransform::get_double() const {
	double p = get_p()->get_double();
	return 1.0/(1.0+exp(-p));
}

bool InverseLogitTransform::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		case 0:	// p
			return(dynamic_cast<ContinuousVariable*>(parameter));
		default:
			error("InverseLogitTransform::check_parameter_type(): parameter not found");
	}
	return false;
}

void InverseLogitTransform::set_p(ContinuousVariable* p) {
	set_parameter(0,(Variable*)p);
}

ContinuousVariable const* InverseLogitTransform::get_p() const {
	return (ContinuousVariable const*)get_parameter(0);
}
	
} // namespace gcat

