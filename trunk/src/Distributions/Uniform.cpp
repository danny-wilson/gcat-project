/*  Copyright 2012 Daniel Wilson.
 *
 *  Uniform.cpp
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
#include <Distributions/Uniform.h>

namespace gcat {

const string UniformDistributionParameterNames[2] = {"min","max"};

UniformDistribution::UniformDistribution(string name, DAG* dag) : DAGcomponent(name,dag,"UniformDistribution"), Distribution(UniformDistributionParameterNames,2) {
}

UniformDistribution::UniformDistribution(const UniformDistribution &x) : DAGcomponent(x), Distribution(x) {
}

bool UniformDistribution::check_random_variable_type(RandomVariable* random_variable) {
	return(dynamic_cast<ContinuousVariable*>(random_variable));
	return false;
}

bool UniformDistribution::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		case 0:	//	min
			return(dynamic_cast<ContinuousVariable*>(parameter));
		case 1:	//	max
			return(dynamic_cast<ContinuousVariable*>(parameter));
		default:
			error("UniformDistribution::check_parameter_type(): parameter not found");
	}
	return false;
}

void UniformDistribution::set_min(ContinuousVariable* min) {
	set_parameter(0,(Variable*)min);
}

void UniformDistribution::set_max(ContinuousVariable* max) {
	set_parameter(1,(Variable*)max);
}

ContinuousVariable const*  UniformDistribution::get_min() const {
	return (ContinuousVariable const*)get_parameter(0);
}

ContinuousVariable const*  UniformDistribution::get_max() const {
	return (ContinuousVariable const*)get_parameter(1);
}

mydouble UniformDistribution::likelihood(const RandomVariable* rv, const Value* val) {
	if(val==0) error("UniformDistribution::log_likelihood(): variable not found");
	
	const double a = get_min()->get_double();
	const double b = get_max()->get_double();
	const double x = ((ContinuousVariable*)val)->get_double();
	
	if(x<a || x>b) {
		return mydouble(0);
	}
	return mydouble(1.0/(b-a));
}
	
} // namespace gcat

