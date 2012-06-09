/*  Copyright 2012 Daniel Wilson.
 *
 *  ContinuousMixture.cpp
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
#include <Distributions/ContinuousMixture.h>

namespace gcat {

const string ContinuousMixtureParameterNames[1] = {"p"};
const string ContinuousMixtureDistributionNames[2] = {"distribution0","distribution1"};

ContinuousMixture::ContinuousMixture(string name, DAG* dag) : DAGcomponent(name,dag,"ContinuousMixture"), CompoundDistribution(ContinuousMixtureDistributionNames,2,ContinuousMixtureParameterNames,1) {
}

ContinuousMixture::ContinuousMixture(const ContinuousMixture& x) : DAGcomponent((const DAGcomponent&)x), CompoundDistribution((const CompoundDistribution&)x) {
}

bool ContinuousMixture::check_random_variable_type(RandomVariable* random_variable) {
	return(dynamic_cast<ContinuousVariable*>(random_variable));
	return false;
}

bool ContinuousMixture::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		case 0:	//	p
			return(dynamic_cast<ContinuousVariable*>(parameter));
		default:
			error("ContinuousMixture::check_parameter_type(): parameter not found");
	}
	return false;
}

void ContinuousMixture::set_p(ContinuousVariable* p) {
	set_parameter(0,(Variable*)p);
}

ContinuousVariable const* ContinuousMixture::get_p() const {
	return (ContinuousVariable const*)get_parameter(0);
}

mydouble ContinuousMixture::likelihood(const RandomVariable* rv, const Value* val) {
	_x = ((ContinuousVariable*)val)->get_double();
	const double p = get_p()->get_double();
	if(n_parents()!=2) error("ContinuousMixture::likelihood(): wrong # parent distributions");
	return mydouble(p) * get_parent(0)->likelihood(this,to_Value()) + mydouble(1.0-p) * get_parent(1)->likelihood(this,to_Value());
}

double ContinuousMixture::get_double() const {
	return _x;
}
	
} // namespace gcat

