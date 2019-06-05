/*  Copyright 2017 Daniel Wilson.
 *
 *  ContinuousVectorMoves.h
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
#ifndef _CONTINUOUS_VECTOR_MCMC_MOVES_H_
#define _CONTINUOUS_VECTOR_MCMC_MOVES_H_
#include <Inference/MCMC/Moves.h>
#include <RandomVariables/ContinuousVector.h>

namespace gcat {

	class ContinuousVectorJointUniformProposal : public MetropolisHastings_move {
	protected:
		double _half_width;
		ContinuousVectorRV* y;
	public:
		// Constructor
		ContinuousVectorJointUniformProposal(MCMC* mcmc, vector< string > &target, const double weight, const double half_width=1.0);
		// Return Hastings ratio
		mydouble propose();
		// Implement accept()
		void accept();
		// Implement reject()
		void reject();
	};
	
	class ContinuousVectorJointLogUniformProposal : public MetropolisHastings_move {
	protected:
		double _half_width;
		ContinuousVectorRV* y;
	public:
		// Constructor
		ContinuousVectorJointLogUniformProposal(MCMC* mcmc, vector< string > &target, const double weight, const double half_width=1.0);
		// Return Hastings ratio
		mydouble propose();
		// Implement accept()
		void accept();
		// Implement reject()
		void reject();
	};

} // namespace gcat

#endif //_CONTINUOUS_VECTOR_MCMC_MOVES_H_

