/*  Copyright 2012 Daniel Wilson.
 *
 *  ImproperBeta.cpp
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
#include <Distributions/ImproperBeta.h>

namespace gcat {

const string ImproperBetaDistributionParameterNames[0];

ImproperBetaDistribution::ImproperBetaDistribution(string name, DAG* dag, const double a, const double b) : DAGcomponent(name,dag,"ImproperBetaDistribution"), Distribution(ImproperBetaDistributionParameterNames,0), _a(a), _b(b) {
}

ImproperBetaDistribution::ImproperBetaDistribution(const ImproperBetaDistribution &x) : DAGcomponent(x), Distribution(x) {
}

bool ImproperBetaDistribution::check_random_variable_type(RandomVariable* random_variable) {
	return(dynamic_cast<ContinuousVariable*>(random_variable));
	return false;
}

bool ImproperBetaDistribution::check_parameter_type(const int i, Variable* parameter) {
	error("ImproperBetaDistribution::check_parameter_type(): parameter not found");
	return false;
}

mydouble ImproperBetaDistribution::likelihood(const RandomVariable* rv, const Value* val) {
	if(val==0) error("ImproperBetaDistribution::log_likelihood(): variable not found");
	
	const double x = ((ContinuousVariable*)val)->get_double();
	
	if(x<=0 || x>=1) {
		return mydouble(0);
	}
	mydouble ret;
	ret.setlog((_a-1.0)*log(x)+(_b-1.0)*log(1.0-x));
	return ret;
}
	
} // namespace gcat


