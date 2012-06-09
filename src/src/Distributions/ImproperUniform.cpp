/*  Copyright 2012 Daniel Wilson.
 *
 *  ImproperUniform.cpp
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
#include <Distributions/ImproperUniform.h>
#include <Variables/Continuous.h>

namespace gcat {

const string ImproperUniformDistributionParameterNames[0];

ImproperUniformDistribution::ImproperUniformDistribution(string name, DAG* dag) : DAGcomponent(name,dag,"ImproperUniformDistribution"), Distribution(ImproperUniformDistributionParameterNames,0) {
}

ImproperUniformDistribution::ImproperUniformDistribution(const ImproperUniformDistribution &x) : DAGcomponent(x), Distribution(x) {
}

bool ImproperUniformDistribution::check_random_variable_type(RandomVariable* random_variable) {
	return(dynamic_cast<ContinuousVariable*>(random_variable));
	return false;
}

bool ImproperUniformDistribution::check_parameter_type(const int i, Variable* parameter) {
	error("ImproperUniformDistribution::check_parameter_type(): parameter not found");
	return false;
}

mydouble ImproperUniformDistribution::likelihood(const RandomVariable* rv, const Value* val) {
	if(val==0) error("ImproperUniformDistribution::log_likelihood(): variable not found");
	return mydouble(1);
}
	
} // namespace gcat



