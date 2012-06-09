/*  Copyright 2012 Daniel Wilson.
 *
 *  BetaDistribution.cpp
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
#include <Distributions/Beta.h>

namespace gcat {

const string BetaDistributionParameterNames[2] = {"a","b"};

BetaDistribution::BetaDistribution(string name, DAG* dag) : DAGcomponent(name,dag,"BetaDistribution"), Distribution(BetaDistributionParameterNames,2) {
}

BetaDistribution::BetaDistribution(const BetaDistribution &x) : DAGcomponent((const DAGcomponent &)x), Distribution((const Distribution &)x) {
}

bool BetaDistribution::check_random_variable_type(RandomVariable* random_variable) {
	return(dynamic_cast<ContinuousVariable*>(random_variable));
	return false;
}

bool BetaDistribution::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		case 0:	//	a
			return(dynamic_cast<ContinuousVariable*>(parameter));
		case 1:	//	b
			return(dynamic_cast<ContinuousVariable*>(parameter));
		default:
			error("BetaDistribution::check_parameter_type(): parameter not found");
	}
	return false;
}

void BetaDistribution::set_a(ContinuousVariable* a) {
	set_parameter(0,(Variable*)a);
}

void BetaDistribution::set_b(ContinuousVariable* b) {
	set_parameter(1,(Variable*)b);
}

ContinuousVariable const*  BetaDistribution::get_a() const {
	return (ContinuousVariable const*)get_parameter(0);
}

ContinuousVariable const*  BetaDistribution::get_b() const {
	return (ContinuousVariable const*)get_parameter(1);
}

mydouble BetaDistribution::likelihood(const RandomVariable* rv, const Value* val) {
	if(val==0) error("BetaDistribution::log_likelihood(): variable not found");

	const double a = get_a()->get_double();
	const double b = get_b()->get_double();
	const double x = ((ContinuousVariable*)val)->get_double();
	
	if(x<=0 || x>=1 || a<=0 || b<=0) {
		return mydouble(0);
	}
	mydouble ret;
	ret.setlog((a-1.0)*log(x)+(b-1.0)*log(1.0-x)+lgamma(a+b)-lgamma(a)-lgamma(b));
	return ret;
}
	
} // namespace gcat


