/*  Copyright 2012 Daniel Wilson.
 *
 *  BinomialDistribution.cpp
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
#include <Distributions/Binomial.h>

namespace gcat {

const string BinomialDistributionParameterNames[2] = {"N","p"};

BinomialDistribution::BinomialDistribution(string name, DAG* dag) : DAGcomponent(name,dag,"BinomialDistribution"), Distribution(BinomialDistributionParameterNames,2) {
}

BinomialDistribution::BinomialDistribution(const BinomialDistribution &x) : DAGcomponent((const DAGcomponent &)x), Distribution((const Distribution &)x) {
}

bool BinomialDistribution::check_random_variable_type(RandomVariable* random_variable) {
	return(dynamic_cast<DiscreteVariable*>(random_variable));
	return false;
}

bool BinomialDistribution::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		case 0:	//	N
			return(dynamic_cast<DiscreteVariable*>(parameter));
		case 1:	//	p
			return(dynamic_cast<ContinuousVariable*>(parameter));
		default:
			error("BinomialDistribution::check_parameter_type(): parameter not found");
	}
	return false;
}

void BinomialDistribution::set_N(DiscreteVariable* N) {
	set_parameter(0,(Variable*)N);
}

void BinomialDistribution::set_p(ContinuousVariable* p) {
	set_parameter(1,(Variable*)p);
}

DiscreteVariable const*  BinomialDistribution::get_N() const {
	return (DiscreteVariable const*)get_parameter(0);
}

ContinuousVariable const*  BinomialDistribution::get_p() const {
	return (ContinuousVariable const*)get_parameter(1);
}

mydouble BinomialDistribution::likelihood(const RandomVariable* rv, const Value* val) {
	if(val==0) error("BinomialDistribution::log_likelihood(): variable not found");
	
	const int N = get_N()->get_int();
	const double p = get_p()->get_double();
	const int X = ((DiscreteVariable*)val)->get_int();

	if(X<0 || X>N || p<0 || p>1) {
		return mydouble(0);
	}
	mydouble ret;
	ret.setlog(lgamma(N+1)-lgamma(X+1)-lgamma(N-X+1)+(double)X*log(p)+(double)(N-X)*log(1.0-p));
	return ret;
}
	
} // namespace gcat

