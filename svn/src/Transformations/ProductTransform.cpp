/*  Copyright 2012 Daniel Wilson.
 *
 *  ProductTransform.cpp
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
#include <Transformations/ProductTransform.h>
#include <string>
#include <sstream>

using std::string;
using std::stringstream;

namespace gcat {

const string* ProductTransformParameterNames(const int n) {
	string* ret = new string[n];
	int i;
	for(i=0;i<n;i++) {
		stringstream s;
		s << "operand" << i;
		ret[i] = s.str();
	}
	return ret;
}

ProductTransform::ProductTransform(const int n, string name, DAG* dag) : DAGcomponent(name,dag,"ProductTransform"), Transformation(ProductTransformParameterNames(n),n), _n(n) {
}

ProductTransform::ProductTransform(const ProductTransform& x) : DAGcomponent(x), Transformation(x), _n(x._n) {
}

double ProductTransform::get_double() const {
	int i;
	double ret = ((const ContinuousVariable*)get_parameter(0))->get_double();
	for(i=1;i<_n;i++) {
		ret *= ((const ContinuousVariable*)get_parameter(i))->get_double();
	}
	return ret;
}

bool ProductTransform::check_parameter_type(const int i, Variable* parameter) {
	return(dynamic_cast<ContinuousVariable*>(parameter));
}
	
} // namespace gcat
