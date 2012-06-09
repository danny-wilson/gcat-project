/*  Copyright 2012 Daniel Wilson.
 *
 *  LogUniform.cpp
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
#include <Distributions/LogUniform.h>

namespace gcat {

const string LogUniformDistributionParameterNames[2] = {"min","max"};

LogUniformDistribution::LogUniformDistribution(string name, DAG* dag) : DAGcomponent(name,dag,"LogUniformDistribution"), Distribution(LogUniformDistributionParameterNames,2) {
}

LogUniformDistribution::LogUniformDistribution(const LogUniformDistribution &x) : DAGcomponent(x), Distribution(x) {
}

bool LogUniformDistribution::check_random_variable_type(RandomVariable* random_variable) {
	return(dynamic_cast<ContinuousVariable*>(random_variable));
	return false;
}

bool LogUniformDistribution::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		case 0:	//	min
			return(dynamic_cast<ContinuousVariable*>(parameter));
		case 1:	//	max
			return(dynamic_cast<ContinuousVariable*>(parameter));
		default:
			error("NormalDistribution::check_parameter_type(): parameter not found");
	}
	return false;
}

void LogUniformDistribution::set_min(ContinuousVariable* min) {
	set_parameter(0,(Variable*)min);
}

void LogUniformDistribution::set_max(ContinuousVariable* max) {
	set_parameter(1,(Variable*)max);
}

ContinuousVariable const* LogUniformDistribution::get_min() const {
	return (ContinuousVariable const*)get_parameter(0);
}

ContinuousVariable const*  LogUniformDistribution::get_max() const {
	return (ContinuousVariable const*)get_parameter(1);
}

mydouble LogUniformDistribution::likelihood(const RandomVariable* rv, const Value* val) {
	if(val==0) error("LogUniformDistribution::log_likelihood(): variable not found");
	
	const double min = get_min()->get_double();
	const double max = get_max()->get_double();
	const double x = ((ContinuousVariable*)val)->get_double();
	
	if(min<=0 || max<=min || x<=min || x>=max) {
		return mydouble(0);
	}
	mydouble ret = 1.0/x/log(max/min);
	return ret;
}
	
} // namespace gcat

