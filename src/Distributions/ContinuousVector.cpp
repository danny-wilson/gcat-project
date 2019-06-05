/*  Copyright 2017 Daniel Wilson.
 *
 *  ContinuousVector.cpp
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
// This code based on ContinuousMosaic.cpp
#include <Distributions/ContinuousVector.h>
#include <RandomVariables/ContinuousVector.h>

namespace gcat {

const string ContinuousVectorParameterNames[0];
const string ContinuousVectorDistributionNames[1] = {"marginal"};

ContinuousVectorDistribution::ContinuousVectorDistribution(string name, DAG* dag) : DAGcomponent(name,dag,"ContinuousVectorDistribution"), CompoundDistribution(ContinuousVectorDistributionNames,1,ContinuousVectorParameterNames,0) {
}

ContinuousVectorDistribution::ContinuousVectorDistribution(const ContinuousVectorDistribution& x) : DAGcomponent((const DAGcomponent&)x), CompoundDistribution((const CompoundDistribution&)x) {
}

bool ContinuousVectorDistribution::check_random_variable_type(RandomVariable* random_variable) {
	// Not clear the following is true for ContinuousVectors
	// Unlike ContinuousVariable vs ContinuousRV, must require a type of ContinuousVector RV because
	// it guarantees extra derived functions: last_move(), last_change_value(), etc
	return(dynamic_cast<ContinuousVectorRV*>(random_variable));
	return false;
}

bool ContinuousVectorDistribution::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		default:
			error("ContinuousVectorDistribution::check_parameter_type(): parameter not found");
	}
	return false;
}

Distribution* ContinuousVectorDistribution::get_marginal_distribution() {
	return get_parent(0);
}

mydouble ContinuousVectorDistribution::likelihood(const RandomVariable* rv, const Value* val) {
	ContinuousVectorRV& y = *(ContinuousVectorRV*)val;
	mydouble lik(1.0);
	int i;
	for(i=0;i<y.length();i++) {
		_x = y.get_double(i);
		lik *= get_marginal_distribution()->likelihood(this,to_Value());
	}
	//std::cout << "ContinuousVectorDistribution::likelihood(): log-lik = " << lik.LOG() << std::endl;
	return lik;
}

double ContinuousVectorDistribution::get_double() const {
	return _x;
}

} // namespace gcat
