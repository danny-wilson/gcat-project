/*  Copyright 2012 Daniel Wilson.
 *
 *  Normal.cpp
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
#include <Distributions/Normal.h>

namespace gcat {

const string NormalDistributionParameterNames[2] = {"mean","sd"};

NormalDistribution::NormalDistribution(string name, DAG* dag) : DAGcomponent(name,dag,"NormalDistribution"), Distribution(NormalDistributionParameterNames,2), PI(3.141592653589793238) {
}

NormalDistribution::NormalDistribution(const NormalDistribution &x) : DAGcomponent(x), Distribution(x), PI(3.141592653589793238) {
}

bool NormalDistribution::check_random_variable_type(RandomVariable* random_variable) {
	return(dynamic_cast<ContinuousVariable*>(random_variable));
	return false;
}

bool NormalDistribution::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		case 0:	//	mean
			return(dynamic_cast<ContinuousVariable*>(parameter));
		case 1:	//	sd
			return(dynamic_cast<ContinuousVariable*>(parameter));
		default:
			error("NormalDistribution::check_parameter_type(): parameter not found");
	}
	return false;
}

void NormalDistribution::set_mean(ContinuousVariable* mean) {
	set_parameter(0,(Variable*)mean);
}

void NormalDistribution::set_sd(ContinuousVariable* sd) {
	set_parameter(1,(Variable*)sd);
}

ContinuousVariable const*  NormalDistribution::get_mean() const {
	return (ContinuousVariable const*)get_parameter(0);
}

ContinuousVariable const*  NormalDistribution::get_sd() const {
	return (ContinuousVariable const*)get_parameter(1);
}

mydouble NormalDistribution::likelihood(const RandomVariable* rv, const Value* val) {
	if(val==0) error("NormalDistribution::log_likelihood(): variable not found");
	
	const double m = get_mean()->get_double();
	const double s = get_sd()->get_double();
	const double x = ((ContinuousVariable*)val)->get_double();
	
	if(s<=0) {
		return mydouble(0);
	}
	mydouble ret;
	ret.setlog(-(x-m)*(x-m)/2/s/s-0.5*log(2*PI*s*s));
	return ret;
}
	
} // namespace gcat

