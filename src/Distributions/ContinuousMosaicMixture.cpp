/*  Copyright 2019 Daniel Wilson.
 *
 *  ContinuousMosaicMixture.cpp
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
#include <Distributions/ContinuousMosaicMixture.h>
#include <RandomVariables/ContinuousMosaic.h>

namespace gcat {

const string ContinuousMosaicParameterNames[2] = {"p","m"};
const string ContinuousMosaicMixtureDistributionNames[1] = {"marginal"};

ContinuousMosaicMixtureDistribution::ContinuousMosaicMixtureDistribution(string name, DAG* dag) : DAGcomponent(name,dag,"ContinuousMosaicMixtureDistribution"), CompoundDistribution(ContinuousMosaicMixtureDistributionNames,1,ContinuousMosaicParameterNames,2), _x(0.0), /*_likelihood(0.0), _previous_likelihood(0.0),*/ _calculate_likelihood(true) {
}

ContinuousMosaicMixtureDistribution::ContinuousMosaicMixtureDistribution(const ContinuousMosaicMixtureDistribution& x) : DAGcomponent((const DAGcomponent&)x), CompoundDistribution((const CompoundDistribution&)x), _x(x._x), /*_likelihood(x._likelihood), _previous_likelihood(x._previous_likelihood),*/ _calculate_likelihood(x._calculate_likelihood) {
}

bool ContinuousMosaicMixtureDistribution::check_random_variable_type(RandomVariable* random_variable) {
	// Unlike ContinuousVariable vs ContinuousRV, must require a type of ContinuousMosaic RV because
	// it guarantees extra derived functions: last_move(), last_change_value(), etc
	return(dynamic_cast<ContinuousMosaicRV*>(random_variable));
	return false;
}

bool ContinuousMosaicMixtureDistribution::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
        case 0:	//	p
            return(dynamic_cast<ContinuousVectorVariable*>(parameter));
        case 1:	//	m
            return(dynamic_cast<ContinuousVectorVariable*>(parameter));
		default:
			error("ContinuousMosaicMixtureDistribution::check_parameter_type(): parameter not found");
	}
	return false;
}

void ContinuousMosaicMixtureDistribution::set_p(ContinuousVectorVariable* p) {
	set_parameter(0,(Variable*)p);
}

void ContinuousMosaicMixtureDistribution::set_m(ContinuousVectorVariable* m) {
	set_parameter(1,(Variable*)m);
}


ContinuousVectorVariable const* ContinuousMosaicMixtureDistribution::get_p() const {
	return (ContinuousVectorVariable const*)get_parameter(0);
}

ContinuousVectorVariable const* ContinuousMosaicMixtureDistribution::get_m() const {
	return (ContinuousVectorVariable const*)get_parameter(1);
}

Distribution* ContinuousMosaicMixtureDistribution::get_marginal_distribution() {
	return get_parent(0);
}

mydouble ContinuousMosaicMixtureDistribution::likelihood(const RandomVariable* rv, const Value* val) {
	ContinuousMosaicRV& y = *(ContinuousMosaicRV*)val;
	ContinuousMosaicRV::ContinuousMosaicMoveType move = y.last_move();
	mydouble likelihood;
	if(_calculate_likelihood/* || move==ContinuousMosaicRV::NO_CHANGE*/) {
		likelihood = full_likelihood(y);
	}
	else if(move==ContinuousMosaicRV::NO_CHANGE) {
//		error("ContinuousMosaicMixtureDistribution::likelihood(): shouldn't reach here");
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
	else error("ContinuousMosaicMixtureDistribution::likelihood(): unexpected move");
	return likelihood;
}

mydouble ContinuousMosaicMixtureDistribution::full_likelihood(const ContinuousMosaicRV& y) {
//	_calculate_likelihood = false;

	const vector<double> p = get_p()->get_doubles();
	vector<double> m = get_m()->get_doubles();
	// Number of components
	const int k = p.size();
	// Return zero likelihood if parameters take invalid values
	if(k==0 || m.size()!=k) return mydouble::zero();
	double summ = 0.0;
	int j;
	for(j=0;j<k;j++) {
		if(p[j]<0.0 || p[j]>1.0) return mydouble::zero();
		if(m[j]<0.0) return mydouble::zero();
		summ += m[j];
	}
	if(summ==0.0) return mydouble::zero();
	for(j=0;j<k;j++) {
		m[j] /= summ;
	}

	mydouble lik(1.0);
	int blockstart = -1;
	int i;
	for(i=0;i<y.length();i++) {
		// Does a new block start here (by definition it does for i==0)
		bool breakpoint = y.is_block_start(i);
		// Marginal distribution likelihood
		if(i==0 || breakpoint) {
			_x = y.get_double(i);
			lik *= get_marginal_distribution()->likelihood(this,to_Value());
		}
		// Block length likelihood
		if(i==0 || breakpoint) {
			double liki = 0.0;
			const int blocklen = i-blockstart;
			if(blockstart==-1) {
				// Do nothing - only update likelihood for the *previous* block
				liki = 1.0;
			} else if(blockstart==0) {
				// Previous block length is *at least* blocklen
				for(j=0;j<k;j++) {
					liki += m[j]*pow(1-p[j],blocklen-1);
				}
			} else {
				// Previous block length is blocklen
				for(j=0;j<k;j++) {
					liki += m[j]*pow(1-p[j],blocklen-1)*p[j];
				}
			}
			blockstart = i;
			// Update the likelihood
			lik *= mydouble(liki);
		}
	}
	// The last block has length *at least* blocklen
	const int blocklen = i-blockstart;
	double liki = 0.0;
	for(j=0;j<k;j++) {
		liki += m[j]*pow(1-p[j],blocklen-1);
	}
	// Update the likelihood
	lik *= mydouble(liki);

	// Return the likelihood
	return lik;
}

mydouble ContinuousMosaicMixtureDistribution::partial_likelihood_change_value(const ContinuousMosaicRV& y) {
	mydouble lik(1.0);
	_x = y.last_change_value().from;
	lik /= get_marginal_distribution()->likelihood(this,to_Value());
	_x = y.last_change_value().to;
	lik *= get_marginal_distribution()->likelihood(this,to_Value());
	return lik;
}

mydouble ContinuousMosaicMixtureDistribution::partial_likelihood_extend_block(const ContinuousMosaicRV& y) {
	mydouble lik(1.0);
	// No change in marginal distribution likelihoods
	// Block length likelihood ratio
	// The left-most block start is never moved because it starts at zero by definition
	// There will always be at least two blocks because otherwise block start cannot be moved
	const int old_block_start = y.last_extend_block().old_block_start;
	const int new_block_start = y.last_extend_block().new_block_start;
	if(old_block_start==new_block_start) return lik;
	// Label the two blocks involved 'left_block' and 'this_block'
	// Find the other boundaries
	const int left_block_start = y.block_start(new_block_start-1);
	const int this_block_end = y.block_end(new_block_start);
	// Determine whether each is censored, meaning it is the left-most or right-most block
	const bool left_block_censored = (left_block_start==0);
	const bool this_block_censored = (this_block_end==y.length()-1);
	// Find the length of each block, before and after the move
	const int old_left_block_len = old_block_start-left_block_start;
	const int new_left_block_len = new_block_start-left_block_start;
	const int old_this_block_len = this_block_end-old_block_start+1;
	const int new_this_block_len = this_block_end-new_block_start+1;
	// Find the parameters
	const vector<double> p = get_p()->get_doubles();
	vector<double> m = get_m()->get_doubles();
	// Number of components
	const int k = p.size();
	// Return zero likelihood if parameters take invalid values
	if(k==0 || m.size()!=k) return mydouble::zero();
	double summ = 0.0;
	int j;
	for(j=0;j<k;j++) {
		if(p[j]<0.0 || p[j]>1.0) return mydouble::zero();
		if(m[j]<0.0) return mydouble::zero();
		summ += m[j];
	}
	if(summ==0.0) return mydouble::zero();
	for(j=0;j<k;j++) {
		m[j] /= summ;
	}
	// Calculate the likelihood ratio
	double old_left_lik = 0.0;
	double old_this_lik = 0.0;
	double new_left_lik = 0.0;
	double new_this_lik = 0.0;
	for(j=0;j<k;j++) {
		old_left_lik += (left_block_censored) ? m[j]*pow(1-p[j],old_left_block_len-1) : m[j]*pow(1-p[j],old_left_block_len-1)*p[j];
		new_left_lik += (left_block_censored) ? m[j]*pow(1-p[j],new_left_block_len-1) : m[j]*pow(1-p[j],new_left_block_len-1)*p[j];
		old_this_lik += (this_block_censored) ? m[j]*pow(1-p[j],old_this_block_len-1) : m[j]*pow(1-p[j],old_this_block_len-1)*p[j];
		new_this_lik += (this_block_censored) ? m[j]*pow(1-p[j],new_this_block_len-1) : m[j]*pow(1-p[j],new_this_block_len-1)*p[j];
	}
	// Multiply everything together
	mydouble OLD_LEFT_LIK, NEW_LEFT_LIK, OLD_THIS_LIK, NEW_THIS_LIK;
	OLD_LEFT_LIK.setlog(old_left_lik);
	NEW_LEFT_LIK.setlog(new_left_lik);
	OLD_THIS_LIK.setlog(old_this_lik);
	NEW_THIS_LIK.setlog(new_this_lik);
	lik *= NEW_LEFT_LIK/OLD_LEFT_LIK * NEW_THIS_LIK/OLD_THIS_LIK;
	
	return lik;
}

mydouble ContinuousMosaicMixtureDistribution::partial_likelihood_merge_blocks(const ContinuousMosaicRV& y) {
	mydouble lik(1.0);
	// Marginal distribution likelihood ratio
	_x = y.last_merge_blocks().from[0];
	lik /= get_marginal_distribution()->likelihood(this,to_Value());
	_x = y.last_merge_blocks().from[1];
	lik /= get_marginal_distribution()->likelihood(this,to_Value());
	_x = y.last_merge_blocks().to;
	lik *= get_marginal_distribution()->likelihood(this,to_Value());

	// Block length likelihood ratio
	// Label the two blocks involved 'left_block' and 'this_block'
	// Obtain the position of the boundary to be merged across
	const int this_block_start = y.last_merge_blocks().right_block_start;
	// Find the other boundaries
	const int left_block_start = y.block_start(this_block_start-1);
	const int this_block_end = y.block_end(this_block_start);
	// Determine whether each is censored, meaning it is the left-most or right-most block
	const bool left_block_censored = (left_block_start==0);
	const bool this_block_censored = (this_block_end==y.length()-1);
	// Find the length of each block, before and after the move
	const int left_block_len = this_block_start-left_block_start;
	const int this_block_len = this_block_end-this_block_start+1;
	const int full_block_len = left_block_len+this_block_len;
	// Find the parameters
	const vector<double> p = get_p()->get_doubles();
	vector<double> m = get_m()->get_doubles();
	// Number of components
	const int k = p.size();
	// Return zero likelihood if parameters take invalid values
	if(k==0 || m.size()!=k) return mydouble::zero();
	double summ = 0.0;
	int j;
	for(j=0;j<k;j++) {
		if(p[j]<0.0 || p[j]>1.0) return mydouble::zero();
		if(m[j]<0.0) return mydouble::zero();
		summ += m[j];
	}
	if(summ==0.0) return mydouble::zero();
	for(j=0;j<k;j++) {
		m[j] /= summ;
	}
	// Calculate the likelihood ratio
	double old_left_lik = 0.0;
	double old_this_lik = 0.0;
	double new_lik = 0.0;
	for(j=0;j<k;j++) {
		old_left_lik += (left_block_censored) ? m[j]*pow(1-p[j],left_block_len-1) : m[j]*pow(1-p[j],left_block_len-1)*p[j];
		old_this_lik += (this_block_censored) ? m[j]*pow(1-p[j],this_block_len-1) : m[j]*pow(1-p[j],this_block_len-1)*p[j];
		new_lik += (left_block_censored || this_block_censored) ? m[j]*pow(1-p[j],full_block_len-1) : m[j]*pow(1-p[j],full_block_len-1)*p[j];
	}
	// Multiply everything together
	mydouble OLD_LEFT_LIK, OLD_THIS_LIK, NEW_LIK;
	OLD_LEFT_LIK.setlog(old_left_lik);
	OLD_THIS_LIK.setlog(old_this_lik);
	NEW_LIK.setlog(new_lik);
	lik *= NEW_LIK/OLD_LEFT_LIK/OLD_THIS_LIK;
	
	return lik;
}

mydouble ContinuousMosaicMixtureDistribution::partial_likelihood_split_block(const ContinuousMosaicRV& y) {
	mydouble lik(1.0);
	// Marginal distribution likelihood ratio
	_x = y.last_split_block().from;
	lik /= get_marginal_distribution()->likelihood(this,to_Value());
	_x = y.last_split_block().to[0];
	lik *= get_marginal_distribution()->likelihood(this,to_Value());
	_x = y.last_split_block().to[1];
	lik *= get_marginal_distribution()->likelihood(this,to_Value());

	// Block length likelihood ratio
	// Label the two blocks involved 'left_block' and 'this_block'
	// Obtain the position of the boundary at which to split
	const int this_block_start = y.last_split_block().right_block_start;
	// Find the other boundaries
	const int left_block_start = y.block_start(this_block_start-1);
	const int this_block_end = y.block_end(this_block_start);
	// Determine whether each is censored, meaning it is the left-most or right-most block
	const bool left_block_censored = (left_block_start==0);
	const bool this_block_censored = (this_block_end==y.length()-1);
	// Find the length of each block, before and after the move
	const int left_block_len = this_block_start-left_block_start;
	const int this_block_len = this_block_end-this_block_start+1;
	const int full_block_len = left_block_len+this_block_len;
	// Find the parameters
	const vector<double> p = get_p()->get_doubles();
	vector<double> m = get_m()->get_doubles();
	// Number of components
	const int k = p.size();
	// Return zero likelihood if parameters take invalid values
	if(k==0 || m.size()!=k) return mydouble::zero();
	double summ = 0.0;
	int j;
	for(j=0;j<k;j++) {
		if(p[j]<0.0 || p[j]>1.0) return mydouble::zero();
		if(m[j]<0.0) return mydouble::zero();
		summ += m[j];
	}
	if(summ==0.0) return mydouble::zero();
	for(j=0;j<k;j++) {
		m[j] /= summ;
	}
	// Calculate the likelihood ratio
	double old_lik = 0.0;
	double new_left_lik = 0.0;
	double new_this_lik = 0.0;
	for(j=0;j<k;j++) {
		old_lik += (left_block_censored || this_block_censored) ? m[j]*pow(1-p[j],full_block_len-1) : m[j]*pow(1-p[j],full_block_len-1)*p[j];
		new_left_lik += (left_block_censored) ? m[j]*pow(1-p[j],left_block_len-1) : m[j]*pow(1-p[j],left_block_len-1)*p[j];
		new_this_lik += (this_block_censored) ? m[j]*pow(1-p[j],this_block_len-1) : m[j]*pow(1-p[j],this_block_len-1)*p[j];
	}
	// Multiply everything together
	mydouble OLD_LIK, NEW_LEFT_LIK, NEW_THIS_LIK;
	OLD_LIK.setlog(old_lik);
	NEW_LEFT_LIK.setlog(new_left_lik);
	NEW_THIS_LIK.setlog(new_this_lik);
	lik = NEW_LEFT_LIK*NEW_THIS_LIK/OLD_LIK;

	return lik;
}

double ContinuousMosaicMixtureDistribution::get_double() const {
	return _x;
}

// Beware: multiple signals coming from parent Parameter(s) and Distribution(s)
void ContinuousMosaicMixtureDistribution::receive_signal_from_parent(const Distribution* dist, const Signal sgl) {
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
	else error("ContinuousMosaicMixtureDistribution::receive_signal_from_parent(Distribution*,Signal): unexpected Signal");
	// Call default implementation (propagate to child RVs)
	CompoundDistribution::receive_signal_from_parent(dist,sgl);
}

// Beware: multiple signals coming from parent Parameter(s) and Distribution(s)
void ContinuousMosaicMixtureDistribution::receive_signal_from_parent(const Value* v, const Variable::Signal sgl) {
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
	else error("ContinuousMosaicMixtureDistribution::receive_signal_from_parent(Value*,Signal): unexpected Signal");
	// Call default implementation (propagate to child distributions)
	Distribution::receive_signal_from_parent(v,sgl);
}
	
} // namespace gcat
