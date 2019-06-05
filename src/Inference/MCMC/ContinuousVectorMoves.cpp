/*  Copyright 2017 Daniel Wilson.
 *
 *  ContinuousVectorMoves.cpp
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
#include <Inference/MCMC/ContinuousVectorMoves.h>

using std::min;

namespace gcat {

	ContinuousVectorJointUniformProposal::ContinuousVectorJointUniformProposal(MCMC* mcmc, vector< string > &target, const double weight, const double half_width) : MetropolisHastings_move(mcmc,target,weight,"ContinuousVectorJointUniformProposal"), _half_width(half_width) {
		if(_target.size()!=1) error("ContinuousVectorJointUniformProposal: target vector must have 1 element");
		if(_half_width<=0.0) error("ContinuousVectorJointUniformProposal: half width must be positive");
		// Dynamically type-check the variable
		if(!dynamic_cast<ContinuousVectorRV*>(_target[0])) error("ContinuousVectorJointUniformProposal: target type incompatible");
		y = (ContinuousVectorRV*)_target[0];
	}
	
	// Return Hastings ratio
	mydouble ContinuousVectorJointUniformProposal::propose() {
		const vector<double> x = ((ContinuousVectorRV*)_target[0])->get_doubles();
		vector<double> x_prime(x);
		for(int i=0;i<x.size();i++) {
			x_prime[i] += _ran->uniform(-_half_width,_half_width);
		}
		((ContinuousVectorRV*)_target[0])->propose(x_prime);
		return mydouble(1);
	}
	
	void ContinuousVectorJointUniformProposal::accept() {
		((ContinuousVectorRV*)_target[0])->accept();
	}
	
	void ContinuousVectorJointUniformProposal::reject() {
		((ContinuousVectorRV*)_target[0])->revert();
	}
	
	ContinuousVectorJointLogUniformProposal::ContinuousVectorJointLogUniformProposal(MCMC* mcmc, vector< string > &target, const double weight, const double half_width) : MetropolisHastings_move(mcmc,target,weight,"ContinuousVectorJointLogUniformProposal"), _half_width(half_width) {
		if(_target.size()!=1) error("ContinuousVectorJointLogUniformProposal: target vector must have 1 element");
		if(_half_width<=0.0) error("ContinuousVectorJointLogUniformProposal: half width must be positive");
		// Dynamically type-check the variable
		if(!dynamic_cast<ContinuousVectorRV*>(_target[0])) error("ContinuousVectorJointLogUniformProposal: target type incompatible");
		y = (ContinuousVectorRV*)_target[0];
	}
	
	// Return Hastings ratio
	mydouble ContinuousVectorJointLogUniformProposal::propose() {
		const vector<double> x = ((ContinuousVectorRV*)_target[0])->get_doubles();
		vector<double> x_prime(x.size());
		double Usum = 0.0;
		for(int i=0;i<x.size();i++) {
			const double U = _ran->uniform(-_half_width,_half_width);
			Usum += U;
			x_prime[i] = x[i] * exp(U);
			//std::cout << "ContinuousVectorJointLogUniformProposal::propose(): " << i << " from " << x[i] << " to " << x_prime[i] << std::endl;
		}
		((ContinuousVectorRV*)_target[0])->propose(x_prime);
		mydouble ret;
		ret.setlog(Usum);
		//std::cout << "ContinuousVectorJointLogUniformProposal::propose(): Hastings = " << ret.LOG() << std::endl;
		return ret;
	}
	
	void ContinuousVectorJointLogUniformProposal::accept() {
		((ContinuousVectorRV*)_target[0])->accept();
	}
	
	void ContinuousVectorJointLogUniformProposal::reject() {
		((ContinuousVectorRV*)_target[0])->revert();
	}
	
} // namespace gcat

