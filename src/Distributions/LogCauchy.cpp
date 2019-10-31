/*  Copyright 2019 Daniel Wilson.
 *
 *  LogCauchy.cpp
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
#include <Distributions/LogCauchy.h>

namespace gcat {

const string LogCauchyDistributionParameterNames[2] = {"location","scale"};

LogCauchyDistribution::LogCauchyDistribution(string name, DAG* dag) : DAGcomponent(name,dag,"LogCauchyDistribution"), Distribution(LogCauchyDistributionParameterNames,2), PI(3.141592653589793238) {
}

LogCauchyDistribution::LogCauchyDistribution(const LogCauchyDistribution &x) : DAGcomponent(x), Distribution(x), PI(3.141592653589793238) {
}

bool LogCauchyDistribution::check_random_variable_type(RandomVariable* random_variable) {
	return(dynamic_cast<ContinuousVariable*>(random_variable));
	return false;
}

bool LogCauchyDistribution::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		case 0:	//	location
			return(dynamic_cast<ContinuousVariable*>(parameter));
		case 1:	//	scale
			return(dynamic_cast<ContinuousVariable*>(parameter));
		default:
			error("LogCauchyDistribution::check_parameter_type(): parameter not found");
	}
	return false;
}

void LogCauchyDistribution::set_location(ContinuousVariable* location) {
	set_parameter(0,(Variable*)location);
}

void LogCauchyDistribution::set_scale(ContinuousVariable* scale) {
	set_parameter(1,(Variable*)scale);
}

ContinuousVariable const*  LogCauchyDistribution::get_location() const {
	return (ContinuousVariable const*)get_parameter(0);
}

ContinuousVariable const*  LogCauchyDistribution::get_scale() const {
	return (ContinuousVariable const*)get_parameter(1);
}

mydouble LogCauchyDistribution::likelihood(const RandomVariable* rv, const Value* val) {
	if(val==0) error("LogCauchyDistribution::log_likelihood(): variable not found");
	
  const double location = get_location()->get_double();
  const double scale = get_scale()->get_double();
	const double x = ((ContinuousVariable*)val)->get_double();

	if(x<=0.0) {
		return mydouble(0);
	}
  const double xstd = (log(x)-location)/scale;
	return mydouble(1.0/x/PI/scale/(1.0+xstd*xstd));
}
	
} // namespace gcat

