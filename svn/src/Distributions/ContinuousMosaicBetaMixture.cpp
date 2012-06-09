/*  Copyright 2012 Daniel Wilson.
 *
 *  ContinuousMosaicBetaMixture.cpp
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
#include <Distributions/ContinuousMosaicBetaMixture.h>
#include <RandomVariables/ContinuousMosaic.h>

namespace gcat {

const string ContinuousMosaicBetaMixtureParameterNames[2] = {"a","b"};
const string ContinuousMosaicBetaMixtureDistributionNames[1] = {"marginal"};

ContinuousMosaicBetaMixtureDistribution::ContinuousMosaicBetaMixtureDistribution(string name, DAG* dag) : DAGcomponent(name,dag,"ContinuousMosaicBetaMixtureDistribution"), CompoundDistribution(ContinuousMosaicBetaMixtureDistributionNames,1,ContinuousMosaicBetaMixtureParameterNames,2), _x(0.0), /*_likelihood(0.0), _previous_likelihood(0.0),*/ _calculate_likelihood(true) {
}

ContinuousMosaicBetaMixtureDistribution::ContinuousMosaicBetaMixtureDistribution(const ContinuousMosaicBetaMixtureDistribution& x) : DAGcomponent((const DAGcomponent&)x), CompoundDistribution((const CompoundDistribution&)x), _x(x._x), /*_likelihood(x._likelihood), _previous_likelihood(x._previous_likelihood),*/ _calculate_likelihood(x._calculate_likelihood) {
}

bool ContinuousMosaicBetaMixtureDistribution::check_random_variable_type(RandomVariable* random_variable) {
	// Unlike ContinuousVariable vs ContinuousRV, must require a type of ContinuousMosaic RV because
	// it guarantees extra derived functions: last_move(), last_change_value(), etc
	return(dynamic_cast<ContinuousMosaicRV*>(random_variable));
	return false;
}

bool ContinuousMosaicBetaMixtureDistribution::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		case 0:	//	a
			return(dynamic_cast<ContinuousVariable*>(parameter));
		case 1:	//	b
			return(dynamic_cast<ContinuousVariable*>(parameter));
		default:
			error("ContinuousMosaicBetaMixtureDistribution::check_parameter_type(): parameter not found");
	}
	return false;
}

void ContinuousMosaicBetaMixtureDistribution::set_a(ContinuousVariable* a) {
	set_parameter(0,(Variable*)a);
}

void ContinuousMosaicBetaMixtureDistribution::set_b(ContinuousVariable* b) {
	set_parameter(1,(Variable*)b);
}

ContinuousVariable const* ContinuousMosaicBetaMixtureDistribution::get_a() const {
	return (ContinuousVariable const*)get_parameter(0);
}

ContinuousVariable const* ContinuousMosaicBetaMixtureDistribution::get_b() const {
	return (ContinuousVariable const*)get_parameter(1);
}

Distribution* ContinuousMosaicBetaMixtureDistribution::get_marginal_distribution() {
	return get_parent(0);
}

mydouble ContinuousMosaicBetaMixtureDistribution::likelihood(const RandomVariable* rv, const Value* val) {
	ContinuousMosaicRV& y = *(ContinuousMosaicRV*)val;
	ContinuousMosaicRV::ContinuousMosaicMoveType move = y.last_move();
	mydouble likelihood;
	if(_calculate_likelihood/* || move==ContinuousMosaicRV::NO_CHANGE*/) {
		likelihood = full_likelihood(y);
	}
	else if(move==ContinuousMosaicRV::NO_CHANGE) {
		//		error("ContinuousMosaicBetaMixtureDistribution::likelihood(): shouldn't reach here");
		likelihood = full_likelihood(y);
	}
	else if(move==ContinuousMosaicRV::CHANGE_VALUE) {
		likelihood = rv->stored_likelihood() * partial_likelihood_change_value(y);
	}
	else if(move==ContinuousMosaicRV::EXTEND_BLOCK) {
		likelihood = rv->stored_likelihood() * partial_likelihood_extend_block(y);
	}
	else if(move==ContinuousMosaicRV::MERGE_BLOCKS) {
		likelihood = rv->stored_likelihood() * partial_likelihood_merge_blocks(y);
	}
	else if(move==ContinuousMosaicRV::SPLIT_BLOCK) {
		likelihood = rv->stored_likelihood() * partial_likelihood_split_block(y);
	}
	else error("ContinuousMosaicBetaMixtureDistribution::likelihood(): unexpected move");
	return likelihood;
}

mydouble ContinuousMosaicBetaMixtureDistribution::full_likelihood(const ContinuousMosaicRV& y) {
	//	_calculate_likelihood = false;
	
	const double a = get_a()->get_double();
	const double b = get_b()->get_double();
	if(a<=0 || b<=0) return mydouble::zero();
	
	mydouble lik(1.0);
	const double nbp = (double)(y.length()-1);
	double xbp = 0.0;
	int i;
	for(i=0;i<y.length();i++) {
		bool breakpoint = y.is_block_start(i);
		if(i==0 || breakpoint) {
			_x = y.get_double(i);
			lik *= get_marginal_distribution()->likelihood(this,to_Value());
		}
		if(i!=0) xbp += (breakpoint) ? 1 : 0;
	}
	mydouble beta_bin_lik;
	//beta_bin_lik.setlog(lbeta(xbp+a,nbp-xbp+b)-lbeta(a,b));
	beta_bin_lik.setlog(lgamma(xbp+a)+lgamma(nbp-xbp+b)-lgamma(nbp+a+b)-lgamma(a)-lgamma(b)+lgamma(a+b));	
	lik *= beta_bin_lik;
	return lik;
}

mydouble ContinuousMosaicBetaMixtureDistribution::partial_likelihood_change_value(const ContinuousMosaicRV& y) {
	mydouble lik(1.0);
	_x = y.last_change_value().from;
	lik /= get_marginal_distribution()->likelihood(this,to_Value());
	_x = y.last_change_value().to;
	lik *= get_marginal_distribution()->likelihood(this,to_Value());
	return lik;
}

mydouble ContinuousMosaicBetaMixtureDistribution::partial_likelihood_extend_block(const ContinuousMosaicRV& y) {
	return mydouble(1.0);
}

mydouble ContinuousMosaicBetaMixtureDistribution::partial_likelihood_merge_blocks(const ContinuousMosaicRV& y) {
	const double a = get_a()->get_double();
	const double b = get_b()->get_double();
	
	const double nbp = (double)(y.length()-1);
	const double xbp = (double)(y.nblocks()-1);
	mydouble lik;
	//lik.setlog(lbeta(xbp+a,nbp-xbp+b)-lbeta(xbp+1.0+a,nbp-xbp-1.0+b));
	lik.setlog(lgamma(xbp+a)+lgamma(nbp-xbp+b)-lgamma(xbp+1.0+a)-lgamma(nbp-xbp-1.0+b));
	_x = y.last_merge_blocks().from[0];
	lik /= get_marginal_distribution()->likelihood(this,to_Value());
	_x = y.last_merge_blocks().from[1];
	lik /= get_marginal_distribution()->likelihood(this,to_Value());
	_x = y.last_merge_blocks().to;
	lik *= get_marginal_distribution()->likelihood(this,to_Value());
	return lik;
}

mydouble ContinuousMosaicBetaMixtureDistribution::partial_likelihood_split_block(const ContinuousMosaicRV& y) {
	const double a = get_a()->get_double();
	const double b = get_b()->get_double();
	
	const double nbp = (double)(y.length()-1);
	const double xbp = (double)(y.nblocks()-1);
	mydouble lik;
	//lik.setlog(lbeta(xbp+a,nbp-xbp+b)-lbeta(xbp-1.0+a,nbp-xbp+1.0+b));
	lik.setlog(lgamma(xbp+a)+lgamma(nbp-xbp+b)-lgamma(xbp-1.0+a)-lgamma(nbp-xbp+1.0+b));
	_x = y.last_split_block().from;
	lik /= get_marginal_distribution()->likelihood(this,to_Value());
	_x = y.last_split_block().to[0];
	lik *= get_marginal_distribution()->likelihood(this,to_Value());
	_x = y.last_split_block().to[1];
	lik *= get_marginal_distribution()->likelihood(this,to_Value());
	return lik;
}

double ContinuousMosaicBetaMixtureDistribution::get_double() const {
	return _x;
}

// Beware: multiple signals coming from parent Parameter(s) and Distribution(s)
void ContinuousMosaicBetaMixtureDistribution::receive_signal_from_parent(const Distribution* dist, const Signal sgl) {
	if(sgl==Variable::_SET) {
		_calculate_likelihood = true;
	}
	else if(sgl==Variable::_PROPOSE) {
		//		_previous_likelihood = _likelihood;
		_calculate_likelihood = true;
	}
	else if(sgl==Variable::_ACCEPT) {
		_calculate_likelihood = false;
	}
	else if(sgl==Variable::_REVERT) {
		_calculate_likelihood = false;
		//		_likelihood = _previous_likelihood;
	}
	else error("ContinuousMosaicBetaMixtureDistribution::receive_signal_from_parent(Distribution*,Signal): unexpected Signal");
	// Call default implementation (propagate to child RVs)
	CompoundDistribution::receive_signal_from_parent(dist,sgl);
}

// Beware: multiple signals coming from parent Parameter(s) and Distribution(s)
void ContinuousMosaicBetaMixtureDistribution::receive_signal_from_parent(const Value* v, const Variable::Signal sgl) {
	if(sgl==Variable::_SET) {
		_calculate_likelihood = true;
	}
	else if(sgl==Variable::_PROPOSE) {
		//		_previous_likelihood = _likelihood;
		_calculate_likelihood = true;
	}
	else if(sgl==Variable::_ACCEPT) {
	}
	else if(sgl==Variable::_REVERT) {
		//		_likelihood = _previous_likelihood;
	}
	else error("ContinuousMosaicBetaMixtureDistribution::receive_signal_from_parent(Value*,Signal): unexpected Signal");
	// Call default implementation (propagate to child distributions)
	Distribution::receive_signal_from_parent(v,sgl);
}
	
} // namespace gcat
