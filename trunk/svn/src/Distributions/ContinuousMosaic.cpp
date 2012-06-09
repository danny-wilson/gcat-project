/*  Copyright 2012 Daniel Wilson.
 *
 *  ContinuousMosaic.cpp
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
#include <Distributions/ContinuousMosaic.h>
#include <RandomVariables/ContinuousMosaic.h>

namespace gcat {

const string ContinuousMosaicParameterNames[1] = {"p"};
const string ContinuousMosaicDistributionNames[1] = {"marginal"};

ContinuousMosaicDistribution::ContinuousMosaicDistribution(string name, DAG* dag) : DAGcomponent(name,dag,"ContinuousMosaicDistribution"), CompoundDistribution(ContinuousMosaicDistributionNames,1,ContinuousMosaicParameterNames,1), _x(0.0), /*_likelihood(0.0), _previous_likelihood(0.0),*/ _calculate_likelihood(true) {
}

ContinuousMosaicDistribution::ContinuousMosaicDistribution(const ContinuousMosaicDistribution& x) : DAGcomponent((const DAGcomponent&)x), CompoundDistribution((const CompoundDistribution&)x), _x(x._x), /*_likelihood(x._likelihood), _previous_likelihood(x._previous_likelihood),*/ _calculate_likelihood(x._calculate_likelihood) {
}

bool ContinuousMosaicDistribution::check_random_variable_type(RandomVariable* random_variable) {
	// Unlike ContinuousVariable vs ContinuousRV, must require a type of ContinuousMosaic RV because
	// it guarantees extra derived functions: last_move(), last_change_value(), etc
	return(dynamic_cast<ContinuousMosaicRV*>(random_variable));
	return false;
}

bool ContinuousMosaicDistribution::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		case 0:	//	p
			return(dynamic_cast<ContinuousVariable*>(parameter));
		default:
			error("ContinuousMosaicDistribution::check_parameter_type(): parameter not found");
	}
	return false;
}

void ContinuousMosaicDistribution::set_p(ContinuousVariable* p) {
	set_parameter(0,(Variable*)p);
}

ContinuousVariable const* ContinuousMosaicDistribution::get_p() const {
	return (ContinuousVariable const*)get_parameter(0);
}

Distribution* ContinuousMosaicDistribution::get_marginal_distribution() {
	return get_parent(0);
}

mydouble ContinuousMosaicDistribution::likelihood(const RandomVariable* rv, const Value* val) {
	ContinuousMosaicRV& y = *(ContinuousMosaicRV*)val;
	ContinuousMosaicRV::ContinuousMosaicMoveType move = y.last_move();
	mydouble likelihood;
	if(_calculate_likelihood/* || move==ContinuousMosaicRV::NO_CHANGE*/) {
		likelihood = full_likelihood(y);
	}
	else if(move==ContinuousMosaicRV::NO_CHANGE) {
//		error("ContinuousMosaicDistribution::likelihood(): shouldn't reach here");
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
	else error("ContinuousMosaicDistribution::likelihood(): unexpected move");
	return likelihood;
}

mydouble ContinuousMosaicDistribution::full_likelihood(const ContinuousMosaicRV& y) {
//	_calculate_likelihood = false;

	const double p = get_p()->get_double();
	if(p<0 || p>1) return mydouble::zero();
	mydouble success = mydouble(p);
	mydouble failure = mydouble(1-p);

	mydouble lik(1.0);
	int i;
	for(i=0;i<y.length();i++) {
		bool breakpoint = y.is_block_start(i);
		if(i==0 || breakpoint) {
			_x = y.get_double(i);
			lik *= get_marginal_distribution()->likelihood(this,to_Value());
		}
		if(i!=0) lik *= (breakpoint) ? success : failure;
	}
	return lik;
}

mydouble ContinuousMosaicDistribution::partial_likelihood_change_value(const ContinuousMosaicRV& y) {
	mydouble lik(1.0);
	_x = y.last_change_value().from;
	lik /= get_marginal_distribution()->likelihood(this,to_Value());
	_x = y.last_change_value().to;
	lik *= get_marginal_distribution()->likelihood(this,to_Value());
	return lik;
}

mydouble ContinuousMosaicDistribution::partial_likelihood_extend_block(const ContinuousMosaicRV& y) {
	return mydouble(1.0);
}

mydouble ContinuousMosaicDistribution::partial_likelihood_merge_blocks(const ContinuousMosaicRV& y) {
	const double p = get_p()->get_double();
	mydouble success = mydouble(p);
	mydouble failure = mydouble(1-p);
	
	mydouble lik(1.0);
	_x = y.last_merge_blocks().from[0];
	lik /= get_marginal_distribution()->likelihood(this,to_Value());
	_x = y.last_merge_blocks().from[1];
	lik /= get_marginal_distribution()->likelihood(this,to_Value());
	_x = y.last_merge_blocks().to;
	lik *= get_marginal_distribution()->likelihood(this,to_Value());
	lik *= failure/success;
	return lik;
}

mydouble ContinuousMosaicDistribution::partial_likelihood_split_block(const ContinuousMosaicRV& y) {
	const double p = get_p()->get_double();
	mydouble success = mydouble(p);
	mydouble failure = mydouble(1-p);
	
	mydouble lik(1.0);
	_x = y.last_split_block().from;
	lik /= get_marginal_distribution()->likelihood(this,to_Value());
	_x = y.last_split_block().to[0];
	lik *= get_marginal_distribution()->likelihood(this,to_Value());
	_x = y.last_split_block().to[1];
	lik *= get_marginal_distribution()->likelihood(this,to_Value());
	lik *= success/failure;
	return lik;
}

double ContinuousMosaicDistribution::get_double() const {
	return _x;
}

// Beware: multiple signals coming from parent Parameter(s) and Distribution(s)
void ContinuousMosaicDistribution::receive_signal_from_parent(const Distribution* dist, const Signal sgl) {
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
	else error("ContinuousMosaicDistribution::receive_signal_from_parent(Distribution*,Signal): unexpected Signal");
	// Call default implementation (propagate to child RVs)
	CompoundDistribution::receive_signal_from_parent(dist,sgl);
}

// Beware: multiple signals coming from parent Parameter(s) and Distribution(s)
void ContinuousMosaicDistribution::receive_signal_from_parent(const Value* v, const Variable::Signal sgl) {
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
	else error("ContinuousMosaicDistribution::receive_signal_from_parent(Value*,Signal): unexpected Signal");
	// Call default implementation (propagate to child distributions)
	Distribution::receive_signal_from_parent(v,sgl);
}
	
} // namespace gcat
