/*  Copyright 2012 Daniel Wilson.
 *
 *  Gamma.cpp
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
#include <Distributions/Gamma.h>

namespace gcat {

const string GammaDistributionParameterNames[2] = {"shape","scale"};

GammaDistribution::GammaDistribution(string name, DAG* dag) : DAGcomponent(name,dag,"GammaDistribution"), Distribution(GammaDistributionParameterNames,2) {
}

GammaDistribution::GammaDistribution(const GammaDistribution &x) : DAGcomponent(x), Distribution(x) {
}

bool GammaDistribution::check_random_variable_type(RandomVariable* random_variable) {
	return(dynamic_cast<ContinuousVariable*>(random_variable));
	return false;
}

bool GammaDistribution::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		case 0:	//	shape
			return(dynamic_cast<ContinuousVariable*>(parameter));
		case 1:	//	scale
			return(dynamic_cast<ContinuousVariable*>(parameter));
		default:
			error("GammaDistribution::check_parameter_type(): parameter not found");
	}
	return false;
}

void GammaDistribution::set_shape(ContinuousVariable* shape) {
	set_parameter(0,(Variable*)shape);
}

void GammaDistribution::set_scale(ContinuousVariable* scale) {
	set_parameter(1,(Variable*)scale);
}

ContinuousVariable const*  GammaDistribution::get_shape() const {
	return (ContinuousVariable const*)get_parameter(0);
}

ContinuousVariable const*  GammaDistribution::get_scale() const {
	return (ContinuousVariable const*)get_parameter(1);
}

mydouble GammaDistribution::likelihood(const RandomVariable* rv, const Value* val) {
	if(val==0) error("GammaDistribution::log_likelihood(): variable not found");
	
	const double a = get_shape()->get_double();
	const double b = get_scale()->get_double();
	const double x = ((ContinuousVariable*)val)->get_double();
	
	if(x<=0 || a<=0 || b<=0) {
		return mydouble(0);
	}
	mydouble ret;
	ret.setlog((a-1.0)*log(x)-x/b-a*log(b)-lgamma(a));
	return ret;
}
	
} // namespace gcat

