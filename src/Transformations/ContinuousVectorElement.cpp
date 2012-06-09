/*  Copyright 2012 Daniel Wilson.
 *
 *  ContinuousVectorElement.cpp
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
#include <Transformations/ContinuousVectorElement.h>

namespace gcat {

const string ContinuousVectorElementParameterNames[1] = {"vector"};

ContinuousVectorElement::ContinuousVectorElement(const int elem, string name, DAG* dag) : DAGcomponent(name,dag,"ContinuousVectorElement"), Transformation(ContinuousVectorElementParameterNames,1), _elem(elem) {
}

ContinuousVectorElement::ContinuousVectorElement(const ContinuousVectorElement& x) : DAGcomponent(x), Transformation(x), _elem(x._elem) {
}

double ContinuousVectorElement::get_double() const {
	return get_vector()->get_double(_elem);
}

bool ContinuousVectorElement::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		case 0:	// continuous_mosaic
			return(dynamic_cast<ContinuousVectorVariable*>(parameter));
		default:
			error("ContinuousVectorElement::check_parameter_type(): parameter not found");
	}
	return false;
}

void ContinuousVectorElement::set_vector(ContinuousVectorVariable* v) {
	set_parameter(0,(Variable*)v);
}

ContinuousVectorVariable const* ContinuousVectorElement::get_vector() const {
	return (ContinuousVectorVariable const*)get_parameter(0);
}
	
} // namespace gcat

