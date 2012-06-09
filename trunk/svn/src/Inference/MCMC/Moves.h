/*  Copyright 2012 Daniel Wilson.
 *
 *  Moves.h
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
#ifndef _MCMC_MOVES_H_
#define _MCMC_MOVES_H_
#include <Inference/MCMC/MCMC.h>
#include <RandomVariables/Continuous.h>

namespace gcat {

class MetropolisHastings_move : public MCMC_move {
public:
	// Constructor
	MetropolisHastings_move(MCMC* mcmc, vector< string > &target, const double weight, string type="MetropolisHastings_move") : MCMC_move(mcmc,target,weight,type) {
	}
	// Destructor
	virtual ~MetropolisHastings_move() {};
	// Do Metropolis-Hastings
	//		Log the state during the proposal (if necessary)
	//		Record alpha and accept
	//		Set the MCMC likelihood correctly (using appropriate functions)
	void go() {
		mydouble old_likelihood = _mcmc->likelihood();
		mydouble hastings = propose();
		mydouble new_likelihood = _mcmc->update_likelihood();
		// Check....
		/*	if(iter==5500) {
		 _dag->reset_all();
		 mydouble lik2 = _dag->likelihood();
		 if(fabs(lik2.LOG()-_likelihood.LOG())>1e-2) {
		 cout << "\rlik1 = " << _likelihood.LOG() << " lik2 = " << lik2.LOG() << endl;
		 }
		 }*/
		// Log (if necessary)
		_mcmc->record_proposal();
		_mcmc->set_alpha(new_likelihood / old_likelihood * hastings);
		bool _accept = (0 <= _mcmc->alpha().LOG() || _mcmc->ran()->U() < _mcmc->alpha().todouble());
		_mcmc->set_accept(_accept);
		if(_accept) {
			accept();
		}
		else {
			_mcmc->revert_likelihood();
			//_likelihood = old_likelihood;
			reject();
		}
	}
	// Propose the move and return a Hastings ratio
	virtual mydouble propose() = 0;
	// Accept the move
	virtual void accept() = 0;
	// Reject the move
	virtual void reject() = 0;
};

class UniformProposal : public MetropolisHastings_move {
protected:
	double _half_width;
public:
	// Constructor
	UniformProposal(MCMC* mcmc, vector< string > &target, const double weight, const double half_width=1.0) : MetropolisHastings_move(mcmc,target,weight,"UniformProposal"), _half_width(half_width) {
		if(_target.size()!=1) error("UniformProposal: target vector must have 1 element");
		if(_half_width<=0.0) error("UniformProposal: half width must be positive");
		// Dynamically type-check the variable
		if(!dynamic_cast<ContinuousRV*>(_target[0])) error("UniformProposal: target type incompatible");
	}
	// Return Hastings ratio
	mydouble propose() {
		const double x = ((ContinuousRV*)_target[0])->get_double();
		const double x_prime = x + _ran->uniform(-_half_width,_half_width);
		((ContinuousRV*)_target[0])->propose(x_prime);
		return mydouble(1);
	}
	// Implement accept()
	void accept() {
		((ContinuousRV*)_target[0])->accept();
	}
	// Implement reject()
	void reject() {
		((ContinuousRV*)_target[0])->revert();
	}
};

class LogUniformProposal : public MetropolisHastings_move {
protected:
	double _half_width;
public:
	// Constructor
	LogUniformProposal(MCMC* mcmc, vector< string > &target, const double weight, const double half_width=1.0) : MetropolisHastings_move(mcmc,target,weight,"LogUniformProposal"), _half_width(half_width) {
		if(_target.size()!=1) error("LogUniformProposal: target vector must have 1 element");
		if(_half_width<=0.0) error("LogUniformProposal: half width must be positive");
		// Dynamically type-check the variable
		if(!dynamic_cast<ContinuousRV*>(_target[0])) error("LogUniformProposal: target type incompatible");
	}
	// Return Hastings ratio
	mydouble propose() {
		const double x = ((ContinuousRV*)_target[0])->get_double();
		const double U = _ran->uniform(-_half_width,_half_width);
		const double x_prime = x * exp(U);
		((ContinuousRV*)_target[0])->propose(x_prime);
		mydouble ret;
		ret.setlog(U);
		return ret;
	}
	// Implement accept()
	void accept() {
		((ContinuousRV*)_target[0])->accept();
	}
	// Implement reject()
	void reject() {
		((ContinuousRV*)_target[0])->revert();
	}
};

class LogitUniformProposal : public MetropolisHastings_move {
protected:
	double _half_width;
public:
	// Constructor
	LogitUniformProposal(MCMC* mcmc, vector< string > &target, const double weight, const double half_width=1.0) : MetropolisHastings_move(mcmc,target,weight,"LogitUniformProposal"), _half_width(half_width) {
		if(_target.size()!=1) error("LogitUniformProposal: target vector must have 1 element");
		if(_half_width<=0.0) error("LogitUniformProposal: half width must be positive");
		// Dynamically type-check the variable
		if(!dynamic_cast<ContinuousRV*>(_target[0])) error("LogitUniformProposal: target type incompatible");
	}
	// Return Hastings ratio
	mydouble propose() {
		const double x = ((ContinuousRV*)_target[0])->get_double();
		const double U = _ran->uniform(-_half_width,_half_width);
		const double logit_x = log(x/(1.0-x));
		const double logit_x_prime = logit_x+U;
		// Logistic (the inverse) function
		const double x_prime = 1.0/(1.0+exp(-logit_x_prime));
		((ContinuousRV*)_target[0])->propose(x_prime);
		mydouble ret = x_prime*(1.0-x_prime)/x/(1.0-x);
		return ret;
	}
	// Implement accept()
	void accept() {
		((ContinuousRV*)_target[0])->accept();
	}
	// Implement reject()
	void reject() {
		((ContinuousRV*)_target[0])->revert();
	}
};
	
} // namespace gcat


#endif //_MCMC_MOVES_H_
