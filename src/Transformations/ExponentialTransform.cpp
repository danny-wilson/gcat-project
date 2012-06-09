/*  Copyright 2012 Daniel Wilson.
 *
 *  ExponentialTransform.cpp
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
#include <Transformations/ExponentialTransform.h>

namespace gcat {

const string ExponentialTransformParameterNames[1] = {"exponent"};

ExponentialTransform::ExponentialTransform(string name, DAG* dag) : DAGcomponent(name,dag,"ExponentialTransform"), Transformation(ExponentialTransformParameterNames,1) {
}

ExponentialTransform::ExponentialTransform(const ExponentialTransform& x) : DAGcomponent(x), Transformation(x) {
}

double ExponentialTransform::get_double() const {
	double x = get_exponent()->get_double();
	return exp(x);
}

bool ExponentialTransform::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		case 0:	// x
			return(dynamic_cast<ContinuousVariable*>(parameter));
		default:
			error("ExponentialTransform::check_parameter_type(): parameter not found");
	}
	return false;
}

void ExponentialTransform::set_exponent(ContinuousVariable* x) {
	set_parameter(0,(Variable*)x);
}

ContinuousVariable const* ExponentialTransform::get_exponent() const {
	return (ContinuousVariable const*)get_parameter(0);
}
	
} // namespace gcat

