/*  Copyright 2012 Daniel Wilson.
 *
 *  InverseGamma.cpp
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
#include <Distributions/InverseGamma.h>

namespace gcat {

const string InverseGammaDistributionParameterNames[2] = {"shape","scale"};

InverseGammaDistribution::InverseGammaDistribution(string name, DAG* dag) : DAGcomponent(name,dag,"InverseGammaDistribution"), Distribution(InverseGammaDistributionParameterNames,2) {
}

InverseGammaDistribution::InverseGammaDistribution(const InverseGammaDistribution &x) : DAGcomponent(x), Distribution(x) {
}

bool InverseGammaDistribution::check_random_variable_type(RandomVariable* random_variable) {
	return(dynamic_cast<ContinuousVariable*>(random_variable));
	return false;
}

bool InverseGammaDistribution::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		case 0:	//	shape
			return(dynamic_cast<ContinuousVariable*>(parameter));
		case 1:	//	scale
			return(dynamic_cast<ContinuousVariable*>(parameter));
		default:
			error("InverseGammaDistribution::check_parameter_type(): parameter not found");
	}
	return false;
}

void InverseGammaDistribution::set_shape(ContinuousVariable* shape) {
	set_parameter(0,(Variable*)shape);
}

void InverseGammaDistribution::set_scale(ContinuousVariable* scale) {
	set_parameter(1,(Variable*)scale);
}

ContinuousVariable const*  InverseGammaDistribution::get_shape() const {
	return (ContinuousVariable const*)get_parameter(0);
}

ContinuousVariable const*  InverseGammaDistribution::get_scale() const {
	return (ContinuousVariable const*)get_parameter(1);
}

mydouble InverseGammaDistribution::likelihood(const RandomVariable* rv, const Value* val) {
	if(val==0) error("InverseGammaDistribution::log_likelihood(): variable not found");
	
	const double a = get_shape()->get_double();
	const double b = get_scale()->get_double();
	const double x = ((ContinuousVariable*)val)->get_double();
	
	if(x<=0 || a<=0 || b<=0) {
		return mydouble(0);
	}
	mydouble ret;
	ret.setlog(a*log(b)-lgamma(a)-(a+1.0)*log(x)-b/x);
	return ret;
}
	
} // namespace gcat

