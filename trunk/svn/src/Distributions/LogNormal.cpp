/*  Copyright 2012 Daniel Wilson.
 *
 *  LogNormal.cpp
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
#include <Distributions/LogNormal.h>

namespace gcat {

const string LogNormalDistributionParameterNames[2] = {"mean","sd"};

LogNormalDistribution::LogNormalDistribution(string name, DAG* dag) : DAGcomponent(name,dag,"LogNormalDistribution"), Distribution(LogNormalDistributionParameterNames,2), SQRT2PI(2.506628274631) {
}

LogNormalDistribution::LogNormalDistribution(const LogNormalDistribution &x) : DAGcomponent(x), Distribution(x), SQRT2PI(2.506628274631) {
}

bool LogNormalDistribution::check_random_variable_type(RandomVariable* random_variable) {
	return(dynamic_cast<ContinuousVariable*>(random_variable));
	return false;
}

bool LogNormalDistribution::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		case 0:	//	mean
			return(dynamic_cast<ContinuousVariable*>(parameter));
		case 1:	//	sd
			return(dynamic_cast<ContinuousVariable*>(parameter));
		default:
			error("LogNormalDistribution::check_parameter_type(): parameter not found");
	}
	return false;
}

void LogNormalDistribution::set_mean(ContinuousVariable* mean) {
	set_parameter(0,(Variable*)mean);
}

void LogNormalDistribution::set_sd(ContinuousVariable* sd) {
	set_parameter(1,(Variable*)sd);
}

ContinuousVariable const*  LogNormalDistribution::get_mean() const {
	return (ContinuousVariable const*)get_parameter(0);
}

ContinuousVariable const*  LogNormalDistribution::get_sd() const {
	return (ContinuousVariable const*)get_parameter(1);
}

mydouble LogNormalDistribution::likelihood(const RandomVariable* rv, const Value* val) {
	if(val==0) error("LogNormalDistribution::log_likelihood(): variable not found");
	
	const double m = get_mean()->get_double();
	const double s = get_sd()->get_double();
	const double x = ((ContinuousVariable*)val)->get_double();
	const double lnx = log(x);
	
	if(s<=0 || x<=0) {
		return mydouble(0);
	}
	mydouble ret;
	ret.setlog(-(lnx-m)*(lnx-m)/2/s/s-log(SQRT2PI*x*s));
	return ret;
}
	
} // namespace gcat

