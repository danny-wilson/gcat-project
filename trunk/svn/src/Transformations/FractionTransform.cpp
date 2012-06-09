/*  Copyright 2012 Daniel Wilson.
 *
 *  FractionTransform.cpp
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
#include <Transformations/FractionTransform.h>

namespace gcat {

const string FractionTransformParameterNames[2] = {"numerator","denominator"};

FractionTransform::FractionTransform(string name, DAG* dag) : DAGcomponent(name,dag,"FractionTransform"), Transformation(FractionTransformParameterNames,2) {
}

FractionTransform::FractionTransform(const FractionTransform& x) : DAGcomponent(x), Transformation(x) {
}

// NB:- no special behaviour if the fraction is infinite or undefined
double FractionTransform::get_double() const {
	return get_numerator()->get_double()/get_denominator()->get_double();
}

bool FractionTransform::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		case 0:	// numerator
			return(dynamic_cast<ContinuousVariable*>(parameter));
		case 1:	// denominator
			return(dynamic_cast<ContinuousVariable*>(parameter));
		default:
			error("FractionTransform::check_parameter_type(): parameter not found");
	}
	return false;
}

void FractionTransform::set_numerator(ContinuousVariable* x) {
	set_parameter(0,(Variable*)x);
}

void FractionTransform::set_denominator(ContinuousVariable* x) {
	set_parameter(1,(Variable*)x);
}

ContinuousVariable const* FractionTransform::get_numerator() const {
	return (ContinuousVariable const*)get_parameter(0);
}

ContinuousVariable const* FractionTransform::get_denominator() const {
	return (ContinuousVariable const*)get_parameter(1);
}
	
} // namespace gcat

