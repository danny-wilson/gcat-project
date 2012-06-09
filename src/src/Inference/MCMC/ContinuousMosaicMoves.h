/*  Copyright 2012 Daniel Wilson.
 *
 *  ContinuousMosaicMoves.h
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
#ifndef _CONTINUOUS_MOSAIC_MCMC_MOVES_H_
#define _CONTINUOUS_MOSAIC_MCMC_MOVES_H_
#include <Inference/MCMC/Moves.h>
#include <RandomVariables/ContinuousMosaic.h>

namespace gcat {

class ContinuousMosaicUniformProposal : public MetropolisHastings_move, public ContinuousMosaicRV::ChangeValue {
protected:
	double _half_width;
	ContinuousMosaicRV::ChangeValue* _thisContinuousMosaicMoveType;
	ContinuousMosaicRV* y;
public:
	// Constructor
	ContinuousMosaicUniformProposal(MCMC* mcmc, vector< string > &target, const double weight, const double half_width=1.0);
	// Return Hastings ratio
	mydouble propose();
	// Implement accept()
	void accept();
	// Implement reject()
	void reject();
};

class ContinuousMosaicLogUniformProposal : public MetropolisHastings_move, public ContinuousMosaicRV::ChangeValue {
protected:
	double _half_width;
	ContinuousMosaicRV::ChangeValue* _thisContinuousMosaicMoveType;
	ContinuousMosaicRV* y;
public:
	// Constructor
	ContinuousMosaicLogUniformProposal(MCMC* mcmc, vector< string > &target, const double weight, const double half_width=1.0);
	// Return Hastings ratio
	mydouble propose();
	// Implement accept()
	void accept();
	// Implement reject()
	void reject();
};

class ContinuousMosaicExtendBlock : public MetropolisHastings_move, public ContinuousMosaicRV::ExtendBlock {
protected:
	double _p;
	ContinuousMosaicRV::ExtendBlock* _thisContinuousMosaicMoveType;
	ContinuousMosaicRV* y;
	bool _cancel;
public:
	// Constructor
	ContinuousMosaicExtendBlock(MCMC* mcmc, vector< string > &target, const double weight, const double mean_extension=1.2);
	// Return Hastings ratio
	mydouble propose();
	// Implement accept()
	void accept();
	// Implement reject()
	void reject();
};

class ContinuousMosaicSplitMergeBlock : public MetropolisHastings_move {
public:
	enum MeanType {ARITHMETIC, GEOMETRIC};
protected:
	MeanType _mean_type;
	ContinuousMosaicRV::MergeBlocks merge;
	ContinuousMosaicRV::SplitBlock split;
	ContinuousMosaicRV* y;
	double _p;
	bool is_split;
	double split_rate, merge_rate;
public:
	// Constructor
	ContinuousMosaicSplitMergeBlock(MCMC* mcmc, vector< string > &target, const double weight, const double p, const MeanType mean_type=ARITHMETIC);
	// Return Hastings ratio
	mydouble propose();
	mydouble propose_arithmetic_split();
	mydouble propose_arithmetic_merge();
	mydouble propose_geometric_split();
	mydouble propose_geometric_merge();
	// Implement accept()
	void accept();
	// Implement reject()
	void reject();
	// Split rate
	double splitRate(const int nblo, const int L);
	// Merge rate
	double mergeRate(const int nblo, const int L);
};
	
} // namespace gcat

#endif //_CONTINUOUS_MOSAIC_MCMC_MOVES_H_

