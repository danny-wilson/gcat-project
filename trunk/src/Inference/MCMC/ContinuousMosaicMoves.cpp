/*  Copyright 2012 Daniel Wilson.
 *
 *  ContinuousMosaicMoves.cpp
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
#include <algorithm>
#include <Inference/MCMC/ContinuousMosaicMoves.h>

using std::min;

namespace gcat {

ContinuousMosaicUniformProposal::ContinuousMosaicUniformProposal(MCMC* mcmc, vector< string > &target, const double weight, const double half_width) : MetropolisHastings_move(mcmc,target,weight,"ContinuousMosaicUniformProposal"), _half_width(half_width) {
	if(_target.size()!=1) error("ContinuousMosaicUniformProposal: target vector must have 1 element");
	if(_half_width<=0.0) error("ContinuousMosaicUniformProposal: half width must be positive");
	// Dynamically type-check the variable
	if(!dynamic_cast<ContinuousMosaicRV*>(_target[0])) error("ContinuousMosaicUniformProposal: target type incompatible");
	y = (ContinuousMosaicRV*)_target[0];
	_thisContinuousMosaicMoveType = (ContinuousMosaicRV::ChangeValue*)this;
}

mydouble ContinuousMosaicUniformProposal::propose() {
	// Choose a block at random
	int bNum = _ran->discrete(0,y->nblocks()-1);
	position = 0;
	for(;bNum>0;bNum--) {
		position = y->block_end(position)+1;
	}
	from = y->get_double(position);
	to = from + _ran->uniform(-_half_width,_half_width);
	y->change_value(*_thisContinuousMosaicMoveType,Variable::_PROPOSE);
	return mydouble(1);
}

void ContinuousMosaicUniformProposal::accept() {
	y->change_value(*_thisContinuousMosaicMoveType,Variable::_ACCEPT);
}

void ContinuousMosaicUniformProposal::reject() {
	y->change_value(*_thisContinuousMosaicMoveType,Variable::_REVERT);
}

ContinuousMosaicLogUniformProposal::ContinuousMosaicLogUniformProposal(MCMC* mcmc, vector< string > &target, const double weight, const double half_width) : MetropolisHastings_move(mcmc,target,weight,"ContinuousMosaicUniformProposal"), _half_width(half_width) {
	if(_target.size()!=1) error("ContinuousMosaicLogUniformProposal: target vector must have 1 element");
	if(_half_width<=0.0) error("ContinuousMosaicLogUniformProposal: half width must be positive");
	// Dynamically type-check the variable
	if(!dynamic_cast<ContinuousMosaicRV*>(_target[0])) error("ContinuousMosaicLogUniformProposal: target type incompatible");
	y = (ContinuousMosaicRV*)_target[0];
	_thisContinuousMosaicMoveType = (ContinuousMosaicRV::ChangeValue*)this;
}

mydouble ContinuousMosaicLogUniformProposal::propose() {
	// Choose a block at random
	int bNum = _ran->discrete(0,y->nblocks()-1);
	position = 0;
	for(;bNum>0;bNum--) {
		position = y->block_end(position)+1;
	}
	from = y->get_double(position);
	const double U = _ran->uniform(-_half_width,_half_width);
	to = from * exp(U);
	y->change_value(*_thisContinuousMosaicMoveType,Variable::_PROPOSE);
	mydouble ret;
	ret.setlog(U);
	return ret;
}

void ContinuousMosaicLogUniformProposal::accept() {
	y->change_value(*_thisContinuousMosaicMoveType,Variable::_ACCEPT);
}

void ContinuousMosaicLogUniformProposal::reject() {
	y->change_value(*_thisContinuousMosaicMoveType,Variable::_REVERT);
}


ContinuousMosaicExtendBlock::ContinuousMosaicExtendBlock(MCMC* mcmc, vector< string > &target, const double weight, const double mean_extension) : MetropolisHastings_move(mcmc,target,weight,"ContinuousMosaicExtendBlock"), _p(1.0/mean_extension), _cancel(true) {
	if(_target.size()!=1) error("ContinuousMosaicExtendBlock: target vector must have 1 element");
	if(_p>=1.0) error("ContinuousMosaicExtendBlock: mean extension must be greater than 1");
	// Dynamically type-check the variable
	if(!dynamic_cast<ContinuousMosaicRV*>(_target[0])) error("ContinuousMosaicExtendBlock: target type incompatible");
	y = (ContinuousMosaicRV*)_target[0];
	_thisContinuousMosaicMoveType = (ContinuousMosaicRV::ExtendBlock*)this;
}

mydouble ContinuousMosaicExtendBlock::propose() {
	_cancel = false;
	// Choose a block at random (except the left-most)
	const int nblo = y->nblocks();
	if(nblo==1) {
		_cancel = true;
		return mydouble(0.0);
	}
	int bNum = _ran->discrete(0,nblo-2);
	old_block_start = y->block_end(0)+1;
	for(;bNum>0;bNum--) {
		old_block_start = y->block_end(old_block_start)+1;
	}
	bool goLeft = _ran->bernoulliTF(0.5);
	if(goLeft) {
		new_block_start = old_block_start - (_ran->geometric(_p)+1);
		if(new_block_start <= y->block_start(old_block_start-1)) {
			_cancel = true;
			return mydouble(0.0);
		}
	}
	else {
		new_block_start = old_block_start + (_ran->geometric(_p)+1);
		if(new_block_start > y->block_end(old_block_start)) {
			_cancel = true;
			return mydouble(0.0);
		}
	}
	y->extend_block(*_thisContinuousMosaicMoveType,Variable::_PROPOSE);
	return mydouble(1);
}

void ContinuousMosaicExtendBlock::accept() {
	if(_cancel) return;
	y->extend_block(*_thisContinuousMosaicMoveType,Variable::_ACCEPT);
}

void ContinuousMosaicExtendBlock::reject() {
	if(_cancel) return;
	y->extend_block(*_thisContinuousMosaicMoveType,Variable::_REVERT);
}

ContinuousMosaicSplitMergeBlock::ContinuousMosaicSplitMergeBlock(MCMC* mcmc, vector< string > &target, const double weight, const double p, const MeanType mean_type) : MetropolisHastings_move(mcmc,target,weight,"ContinuousMosaicSplitMergeBlock"), _mean_type(mean_type), _p(p), is_split(false) {
	if(_target.size()!=1) error("ContinuousMosaicSplitMergeBlock: target vector must have 1 element");
	if(_p<=0.0 || _p>=1.0) error("ContinuousMosaicSplitMergeBlock: p must be between 0 and 1 exclusive");
	// Dynamically type-check the variable
	if(!dynamic_cast<ContinuousMosaicRV*>(_target[0])) error("ContinuousMosaicSplitMergeBlock: target type incompatible");
	y = (ContinuousMosaicRV*)_target[0];
}

mydouble ContinuousMosaicSplitMergeBlock::propose() {
	// Split or merge?
	split_rate = splitRate(y->nblocks(),y->length());
	merge_rate = mergeRate(y->nblocks(),y->length());
	is_split = _ran->bernoulliTF(split_rate/(split_rate+merge_rate));
	if(_mean_type==ARITHMETIC) {
		return (is_split) ? propose_arithmetic_split() : propose_arithmetic_merge();
	}
	return (is_split) ? propose_geometric_split() : propose_geometric_merge();
}

mydouble ContinuousMosaicSplitMergeBlock::propose_arithmetic_split() {
	/* Choose a position uniformly on [1,L-1] excluding current splits */
	/* The split occurs to the left of the chosen numbered site */
	const int L = y->length();
	const int nblocks = y->nblocks();
	/* K is the number of possible split positions */
	const int K = L - nblocks;
	/* The constant 0.2 determines the efficiency of the breakpoint simulator */
	if((double)K/(double)(L-1)>=0.2) {
		split.right_block_start = _ran->discrete(1,L-1);
		while(true) {
			if(split.right_block_start != y->block_start(split.right_block_start)) break;
			split.right_block_start = _ran->discrete(1,L-1);
		}
	}
	else {
		int pos = _ran->discrete(0,K-1);
		for(split.right_block_start=0;split.right_block_start<L;split.right_block_start++) {
			if(split.right_block_start==y->block_start(split.right_block_start)) ++pos;
			if(split.right_block_start==pos) break;
		}
		if(split.right_block_start==L) error("ContinuousMosaicSplitMergeBlock::propose_split() problem choosing split");
	}
	// Simulate the new blocks' values (ARITHMETIC)
	const int left_block_start = y->block_start(split.right_block_start);
	const int block_end = y->block_end(split.right_block_start);
	split.from = y->get_double(split.right_block_start);
	const double U = _ran->U();
	const double a = (double)(split.right_block_start - left_block_start)/(double)(block_end - left_block_start + 1);
	const double lograt = log(U/(1.-U));
	split.to[0] = split.from + (1.-a)*lograt;
	split.to[1] = split.from - a*lograt;
	// Calculate the Hastings ratio (ARITHMETIC)
	const double reverse_merge_rate = mergeRate(nblocks+1,L);
	const double reverse_split_rate = splitRate(nblocks+1,L);
	double Hastings = (double)K / (double)(nblocks) * reverse_merge_rate * (split_rate+merge_rate) / split_rate / (reverse_split_rate+reverse_merge_rate);
	double Jacobian = 1./U/(1.-U);
	// Implement the move and return the Hastings ratio (which includes a Jacobian term)
	y->split_block(split,Variable::_PROPOSE);
	return mydouble(Hastings*Jacobian);
}

mydouble ContinuousMosaicSplitMergeBlock::propose_arithmetic_merge() {
	/* Merge to left so disallow choosing of the leftmost block */
	const int L = y->length();
	const int nblocks = y->nblocks();
	/*	K is the number of possible split points after the merge
	 i.e. for the complementary reversible jump move			*/
	const int K = L - nblocks + 1;
	// Same scheme as for extend block 
	int bNum = _ran->discrete(0,nblocks-2);
	merge.right_block_start = y->block_end(0)+1;
	for(;bNum>0;bNum--) {
		merge.right_block_start = y->block_end(merge.right_block_start)+1;
	}
	// Simulate the new blocks' values (ARITHMETIC)
	const int left_block_start = y->block_start(merge.right_block_start-1);
	const int block_end = y->block_end(merge.right_block_start);
	merge.from[0] = y->get_double(left_block_start);
	merge.from[1] = y->get_double(merge.right_block_start);
	const double a = (double)(merge.right_block_start - left_block_start)/(double)(block_end - left_block_start + 1);
	merge.to = a*merge.from[0] + (1.-a)*merge.from[1];
	const double U = 1.0/(1.0+exp(merge.from[1]-merge.from[0]));
	// Calculate the Hastings ratio (ARITHMETIC)
	const double reverse_merge_rate = mergeRate(nblocks-1,L);
	const double reverse_split_rate = splitRate(nblocks-1,L);
	const double Hastings = (double)(nblocks-1) / (double)K * reverse_split_rate * (split_rate+merge_rate) / merge_rate / (reverse_split_rate+reverse_merge_rate);
	const double Jacobian = U*(1.-U);
	// Implement the move and return the Hastings ratio (which includes a Jacobian term)
	y->merge_blocks(merge,Variable::_PROPOSE);
	return mydouble(Hastings*Jacobian);
}

mydouble ContinuousMosaicSplitMergeBlock::propose_geometric_split() {
	/* Choose a position uniformly on [1,L-1] excluding current splits */
	/* The split occurs to the left of the chosen numbered site */
	const int L = y->length();
	const int nblocks = y->nblocks();
	/* K is the number of possible split positions */
	const int K = L - nblocks;
	/* The constant 0.2 determines the efficiency of the breakpoint simulator */
	if((double)K/(double)(L-1)>=0.2) {
		split.right_block_start = _ran->discrete(1,L-1);
		while(true) {
			if(split.right_block_start != y->block_start(split.right_block_start)) break;
			split.right_block_start = _ran->discrete(1,L-1);
		}
	}
	else {
		int pos = _ran->discrete(0,K-1);
		for(split.right_block_start=0;split.right_block_start<L;split.right_block_start++) {
			if(split.right_block_start==y->block_start(split.right_block_start)) ++pos;
			if(split.right_block_start==pos) break;
		}
		if(split.right_block_start==L) error("ContinuousMosaicSplitMergeBlock::propose_split() problem choosing split");
	}
	// Simulate the new blocks' values (GEOMETRIC)
	const int left_block_start = y->block_start(split.right_block_start);
	const int block_end = y->block_end(split.right_block_start);
	split.from = y->get_double(split.right_block_start);
	const double U = _ran->U();
	const double a = (double)(split.right_block_start - left_block_start)/(double)(block_end - left_block_start + 1);
	const double rat = U/(1.-U);
	split.to[0] = split.from * pow(rat,1.-a);
	split.to[1] = split.from * pow(rat,-a);
	// Calculate the Hastings ratio (GEOMETRIC)
	const double reverse_merge_rate = mergeRate(nblocks+1,L);
	const double reverse_split_rate = splitRate(nblocks+1,L);
	double Hastings = (double)K / (double)(nblocks) * reverse_merge_rate * (split_rate+merge_rate) / split_rate / (reverse_split_rate+reverse_merge_rate);
	double Jacobian = pow(split.to[0]+split.to[1],2.)/split.from;
	// Implement the move and return the Hastings ratio (which includes a Jacobian term)
	y->split_block(split,Variable::_PROPOSE);
	return mydouble(Hastings*Jacobian);
}

mydouble ContinuousMosaicSplitMergeBlock::propose_geometric_merge() {
	/* Merge to left so disallow choosing of the leftmost block */
	const int L = y->length();
	const int nblocks = y->nblocks();
	/*	K is the number of possible split points after the merge
	 i.e. for the complementary reversible jump move			*/
	const int K = L - nblocks + 1;
	// Same scheme as for extend block 
	int bNum = _ran->discrete(0,nblocks-2);
	merge.right_block_start = y->block_end(0)+1;
	for(;bNum>0;bNum--) {
		merge.right_block_start = y->block_end(merge.right_block_start)+1;
	}
	// Simulate the new blocks' values (GEOMETRIC)
	const int left_block_start = y->block_start(merge.right_block_start-1);
	const int block_end = y->block_end(merge.right_block_start);
	merge.from[0] = y->get_double(left_block_start);
	merge.from[1] = y->get_double(merge.right_block_start);
	const double a = (double)(merge.right_block_start - left_block_start)/(double)(block_end - left_block_start + 1);
	merge.to = pow(merge.from[0],a)*pow(merge.from[1],1.-a);
	// Calculate the Hastings ratio (GEOMETRIC)
	const double reverse_merge_rate = mergeRate(nblocks-1,L);
	const double reverse_split_rate = splitRate(nblocks-1,L);
	const double Hastings = (double)(nblocks-1) / (double)K * reverse_split_rate * (split_rate+merge_rate) / merge_rate / (reverse_split_rate+reverse_merge_rate);
	const double Jacobian = merge.to / pow(merge.from[0]+merge.from[1],2.);
	// Implement the move and return the Hastings ratio (which includes a Jacobian term)
	y->merge_blocks(merge,Variable::_PROPOSE);
	return mydouble(Hastings*Jacobian);
}

void ContinuousMosaicSplitMergeBlock::accept() {
	return (is_split) ? y->split_block(split,Variable::_ACCEPT) : y->merge_blocks(merge,Variable::_ACCEPT);
}

void ContinuousMosaicSplitMergeBlock::reject() {
	return (is_split) ? y->split_block(split,Variable::_REVERT) : y->merge_blocks(merge,Variable::_REVERT);
}

/* relative rate at which splits are proposed */
double ContinuousMosaicSplitMergeBlock::splitRate(const int nblo, const int L) {
	return min((double) 1.0,(double)(L-nblo) / (double)(nblo) * _p / (1.0-_p));
}

/* relative rate at which merges are proposed */
double ContinuousMosaicSplitMergeBlock::mergeRate(const int nblo, const int L) {
	return min(1.0,(double)(nblo-1) / (double)(L-nblo+1) * (1.0-_p) / _p);
}
	
} // namespace gcat

