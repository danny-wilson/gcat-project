/*  Copyright 2012 Daniel Wilson.
 *
 *  MPIMoves.cpp
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
#include <Inference/MCMC/MPIMoves.h>
#include <RandomVariables/Continuous.h>
#include <sstream>

using std::stringstream;

namespace gcat {

extern int MPI_ntasks, MPI_taskid;

MPIUniformProposal::MPIUniformProposal(MCMC* mcmc, vector< string > &target, const double weight, const int handshake, const double half_width) : MCMC_move(mcmc,target,weight,"MPIUniformProposal"), _half_width(half_width), _handshake(handshake), _master(MPI_taskid==0), _ntasks(MPI_ntasks), _recvd(Vector<bool>(MPI_ntasks,false)) {
	if(_target.size()!=1) error("MPIUniformProposal: target vector must have 1 element");
	if(_half_width<=0.0) error("MPIUniformProposal: half width must be positive");
	// Dynamically type-check the variable
	if(!dynamic_cast<ContinuousRV*>(_target[0])) error("MPIUniformProposal: target type incompatible");
}

void MPIUniformProposal::go() {
	if(_master) {
		// Receive handshake, old log-likelihood and parameter value
		_recvd = Vector<bool>(_ntasks,false);
		_recvd[0] = true;
		mydouble old_likelihood = _mcmc->likelihood();
		const double x = ((ContinuousRV*)_target[0])->get_double();
		double msg0[3];
		int i;
		for(i=1;i<_ntasks;i++) {
			// Receive a message from any source with correct handshake
			MPI_Recv(&msg0,3,MPI_DOUBLE,MPI_ANY_SOURCE,_handshake,MPI_COMM_WORLD,&_mpi_status);
			const int source = _mpi_status.MPI_SOURCE;
			// Check message not already received from that source
			if(_recvd[source]) {
				stringstream errTxt;
				errTxt << "MPIUniformProposal::go(): handshake " << _handshake << ".\nAlready received message 0 from source " << source;
				error(errTxt.str().c_str());
			}
			_recvd[source] = true;
			// Check the old parameter value is the same as for the master
			if(msg0[2]!=x) {
				stringstream errTxt;
				errTxt << "MPIUniformProposal::go(): handshake " << _handshake << ". Existing value mismatch.\n";
				errTxt << "Task 0 has " << x << " and task " << source << " has " << msg0[2];
				error(errTxt.str().c_str());
			}
			// Type mydouble sent as a vector of 2 doubles, the log-likelihood and a boolean to indicate if zero
			mydouble old_likelihood_element;
			if((bool)msg0[1]) old_likelihood_element.setzero();
			else old_likelihood_element.setlog(msg0[0]);
			// Update the old likelihood
			old_likelihood *= old_likelihood_element;
		}
		// Make proposal, record Hastings ratio
		double x_prime = x + _ran->uniform(-_half_width,_half_width);
		mydouble hastings = 1;
		// Send proposal
		MPI_Bcast(&x_prime,1,MPI_DOUBLE,0,MPI_COMM_WORLD);
		// Calculate new likelihood & receive new likelihood from other processes
		_recvd = Vector<bool>(_ntasks,false);
		_recvd[0] = true;
		((ContinuousRV*)_target[0])->propose(x_prime);
		mydouble new_likelihood = _mcmc->update_likelihood();
		// Log (if necessary)
		_mcmc->record_proposal();
		double msg1[2];
		for(i=1;i<_ntasks;i++) {
			// Receive a message from any source with correct handshake
			MPI_Recv(&msg1,2,MPI_DOUBLE,MPI_ANY_SOURCE,_handshake,MPI_COMM_WORLD,&_mpi_status);
			const int source = _mpi_status.MPI_SOURCE;
			// Check message not already received from that source
			if(_recvd[source]) {
				stringstream errTxt;
				errTxt << "MPIUniformProposal::go(): handshake " << _handshake << ".\nAlready received message 1 from source " << source;
				error(errTxt.str().c_str());
			}
			_recvd[source] = true;
			// Type mydouble sent as a vector of 2 doubles, the log-likelihood and a boolean to indicate if zero
			mydouble new_likelihood_element;
			if((bool)msg1[1]) new_likelihood_element.setzero();
			else new_likelihood_element.setlog(msg1[0]);
			// Update the new likelihood
			new_likelihood *= new_likelihood_element;
		}
		// Decide whether to accept
		_mcmc->set_alpha(new_likelihood / old_likelihood * hastings);
		bool _accept = (0 <= _mcmc->alpha().LOG() || _mcmc->ran()->U() < _mcmc->alpha().todouble());
		_mcmc->set_accept(_accept);
		// Send instruction whether to accept
		int iaccept = (int)_accept;
		MPI_Bcast(&iaccept,1,MPI_INT,0,MPI_COMM_WORLD);
		// Implement acceptance or rejection
		if(_accept) {
			((ContinuousRV*)_target[0])->accept();
		}
		else {
			_mcmc->revert_likelihood();
			((ContinuousRV*)_target[0])->revert();
		}
	}
	else { // slave
		// Send handshake, old likelihood and parameter value
		mydouble old_likelihood = _mcmc->likelihood();
		const double x = ((ContinuousRV*)_target[0])->get_double();
		double msg0[3] = {old_likelihood.LOG(), (double)old_likelihood.iszero(), x};
		MPI_Send(&msg0,3,MPI_DOUBLE,0,_handshake,MPI_COMM_WORLD);
		// Receive proposal
		double x_prime;
		//MPI_Recv(&xprime,1,MPI_DOUBLE,0,_handshake,MPI_COMM_WORLD,_mpi_status);
		MPI_Bcast(&x_prime,1,MPI_DOUBLE,0,MPI_COMM_WORLD);
		// Calculate new likelihood
		((ContinuousRV*)_target[0])->propose(x_prime);
		mydouble new_likelihood = _mcmc->update_likelihood();
		// Log (if necessary)
		_mcmc->record_proposal();
		// Send new likelihood
		double msg1[2] = {new_likelihood.LOG(), (double)new_likelihood.iszero()};
		MPI_Send(&msg1,2,MPI_DOUBLE,0,_handshake,MPI_COMM_WORLD);
		// Receive instruction whether to accept
		int iaccept;
		MPI_Bcast(&iaccept,1,MPI_INT,0,MPI_COMM_WORLD);
		bool accept = (bool)iaccept;
		// Accept or reject
		_mcmc->set_alpha(new_likelihood/old_likelihood);
		_mcmc->set_accept(accept);
		if(accept) {
			((ContinuousRV*)_target[0])->accept();
		}
		else {
			_mcmc->revert_likelihood();
			((ContinuousRV*)_target[0])->revert();
		}
	}
}

MPILogUniformProposal::MPILogUniformProposal(MCMC* mcmc, vector< string > &target, const double weight, const int handshake, const double half_width) : MCMC_move(mcmc,target,weight,"MPILogUniformProposal"), _half_width(half_width), _handshake(handshake), _master(MPI_taskid==0), _ntasks(MPI_ntasks), _recvd(Vector<bool>(MPI_ntasks,false)) {
	if(_target.size()!=1) error("MPILogUniformProposal: target vector must have 1 element");
	if(_half_width<=0.0) error("MPILogUniformProposal: half width must be positive");
	// Dynamically type-check the variable
	if(!dynamic_cast<ContinuousRV*>(_target[0])) error("MPILogUniformProposal: target type incompatible");
}

void MPILogUniformProposal::go() {
	if(_master) {
		// Receive handshake, old log-likelihood and parameter value
		_recvd = Vector<bool>(_ntasks,false);
		_recvd[0] = true;
		mydouble old_likelihood = _mcmc->likelihood();
		const double x = ((ContinuousRV*)_target[0])->get_double();
		double msg0[3];
		int i;
		for(i=1;i<_ntasks;i++) {
			// Receive a message from any source with correct handshake
			MPI_Recv(&msg0,3,MPI_DOUBLE,MPI_ANY_SOURCE,_handshake,MPI_COMM_WORLD,&_mpi_status);
			const int source = _mpi_status.MPI_SOURCE;
			// Check message not already received from that source
			if(_recvd[source]) {
				stringstream errTxt;
				errTxt << "MPILogUniformProposal::go(): handshake " << _handshake << ".\nAlready received message 0 from source " << source;
				error(errTxt.str().c_str());
			}
			_recvd[source] = true;
			// Check the old parameter value is the same as for the master
			if(msg0[2]!=x) {
				stringstream errTxt;
				errTxt << "MPILogUniformProposal::go(): handshake " << _handshake << ". Existing value mismatch.\n";
				errTxt << "Task 0 has " << x << " and task " << source << " has " << msg0[2];
				error(errTxt.str().c_str());
			}
			// Type mydouble sent as a vector of 2 doubles, the log-likelihood and a boolean to indicate if zero
			mydouble old_likelihood_element;
			if((bool)msg0[1]) old_likelihood_element.setzero();
			else old_likelihood_element.setlog(msg0[0]);
			// Update the old likelihood
			old_likelihood *= old_likelihood_element;
		}
		// Make proposal, record Hastings ratio
		const double U = _ran->uniform(-_half_width,_half_width);
		double x_prime = x * exp(U);
		mydouble hastings;
		hastings.setlog(U);
		// Send proposal
		MPI_Bcast(&x_prime,1,MPI_DOUBLE,0,MPI_COMM_WORLD);
		// Calculate new likelihood & receive new likelihood from other processes
		_recvd = Vector<bool>(_ntasks,false);
		_recvd[0] = true;
		((ContinuousRV*)_target[0])->propose(x_prime);
		mydouble new_likelihood = _mcmc->update_likelihood();
		// Log (if necessary)
		_mcmc->record_proposal();
		double msg1[2];
		for(i=1;i<_ntasks;i++) {
			// Receive a message from any source with correct handshake
			MPI_Recv(&msg1,2,MPI_DOUBLE,MPI_ANY_SOURCE,_handshake,MPI_COMM_WORLD,&_mpi_status);
			const int source = _mpi_status.MPI_SOURCE;
			// Check message not already received from that source
			if(_recvd[source]) {
				stringstream errTxt;
				errTxt << "MPILogUniformProposal::go(): handshake " << _handshake << ".\nAlready received message 1 from source " << source;
				error(errTxt.str().c_str());
			}
			_recvd[source] = true;
			// Type mydouble sent as a vector of 2 doubles, the log-likelihood and a boolean to indicate if zero
			mydouble new_likelihood_element;
			if((bool)msg1[1]) new_likelihood_element.setzero();
			else new_likelihood_element.setlog(msg1[0]);
			// Update the new likelihood
			new_likelihood *= new_likelihood_element;
		}
		// Decide whether to accept
		_mcmc->set_alpha(new_likelihood / old_likelihood * hastings);
		bool _accept = (0 <= _mcmc->alpha().LOG() || _mcmc->ran()->U() < _mcmc->alpha().todouble());
		_mcmc->set_accept(_accept);
		// Send instruction whether to accept
		int iaccept = (int)_accept;
		MPI_Bcast(&iaccept,1,MPI_INT,0,MPI_COMM_WORLD);
		// Implement acceptance or rejection
		if(_accept) {
			((ContinuousRV*)_target[0])->accept();
		}
		else {
			_mcmc->revert_likelihood();
			((ContinuousRV*)_target[0])->revert();
		}
	}
	else { // slave
		// Send handshake, old likelihood and parameter value
		mydouble old_likelihood = _mcmc->likelihood();
		const double x = ((ContinuousRV*)_target[0])->get_double();
		double msg0[3] = {old_likelihood.LOG(), (double)old_likelihood.iszero(), x};
		MPI_Send(&msg0,3,MPI_DOUBLE,0,_handshake,MPI_COMM_WORLD);
		// Receive proposal
		double x_prime;
		//MPI_Recv(&xprime,1,MPI_DOUBLE,0,_handshake,MPI_COMM_WORLD,_mpi_status);
		MPI_Bcast(&x_prime,1,MPI_DOUBLE,0,MPI_COMM_WORLD);
		// Calculate new likelihood
		((ContinuousRV*)_target[0])->propose(x_prime);
		mydouble new_likelihood = _mcmc->update_likelihood();
		// Log (if necessary)
		_mcmc->record_proposal();
		// Send new likelihood
		double msg1[2] = {new_likelihood.LOG(), (double)new_likelihood.iszero()};
		MPI_Send(&msg1,2,MPI_DOUBLE,0,_handshake,MPI_COMM_WORLD);
		// Receive instruction whether to accept
		int iaccept;
		MPI_Bcast(&iaccept,1,MPI_INT,0,MPI_COMM_WORLD);
		bool accept = (bool)iaccept;
		// Accept or reject
		_mcmc->set_alpha(new_likelihood/old_likelihood);
		_mcmc->set_accept(accept);
		if(accept) {
			((ContinuousRV*)_target[0])->accept();
		}
		else {
			_mcmc->revert_likelihood();
			((ContinuousRV*)_target[0])->revert();
		}
	}
}

MPILogItUniformProposal::MPILogItUniformProposal(MCMC* mcmc, vector< string > &target, const double weight, const int handshake, const double half_width) : MCMC_move(mcmc,target,weight,"MPILogItUniformProposal"), _half_width(half_width), _handshake(handshake), _master(MPI_taskid==0), _ntasks(MPI_ntasks), _recvd(Vector<bool>(MPI_ntasks,false)) {
	if(_target.size()!=1) error("MPILogItUniformProposal: target vector must have 1 element");
	if(_half_width<=0.0) error("MPILogItUniformProposal: half width must be positive");
	// Dynamically type-check the variable
	if(!dynamic_cast<ContinuousRV*>(_target[0])) error("MPILogItUniformProposal: target type incompatible");
}

void MPILogItUniformProposal::go() {
	if(_master) {
		// Receive handshake, old log-likelihood and parameter value
		_recvd = Vector<bool>(_ntasks,false);
		_recvd[0] = true;
		mydouble old_likelihood = _mcmc->likelihood();
		const double x = ((ContinuousRV*)_target[0])->get_double();
		double msg0[3];
		int i;
		for(i=1;i<_ntasks;i++) {
			// Receive a message from any source with correct handshake
			MPI_Recv(&msg0,3,MPI_DOUBLE,MPI_ANY_SOURCE,_handshake,MPI_COMM_WORLD,&_mpi_status);
			const int source = _mpi_status.MPI_SOURCE;
			// Check message not already received from that source
			if(_recvd[source]) {
				stringstream errTxt;
				errTxt << "MPILogItUniformProposal::go(): handshake " << _handshake << ".\nAlready received message 0 from source " << source;
				error(errTxt.str().c_str());
			}
			_recvd[source] = true;
			// Check the old parameter value is the same as for the master
			if(msg0[2]!=x) {
				stringstream errTxt;
				errTxt << "MPILogItUniformProposal::go(): handshake " << _handshake << ". Existing value mismatch.\n";
				errTxt << "Task 0 has " << x << " and task " << source << " has " << msg0[2];
				error(errTxt.str().c_str());
			}
			// Type mydouble sent as a vector of 2 doubles, the log-likelihood and a boolean to indicate if zero
			mydouble old_likelihood_element;
			if((bool)msg0[1]) old_likelihood_element.setzero();
			else old_likelihood_element.setlog(msg0[0]);
			// Update the old likelihood
			old_likelihood *= old_likelihood_element;
		}
		// Make proposal, record Hastings ratio
		const double U = _ran->uniform(-_half_width,_half_width);
		const double logit_x = log(x/(1.0-x));
		const double logit_x_prime = logit_x+U;
		// Logistic (the inverse) function
		double x_prime = 1.0/(1.0+exp(-logit_x_prime));
		mydouble hastings = x_prime*(1.0-x_prime)/x/(1.0-x);
		// Send proposal
		MPI_Bcast(&x_prime,1,MPI_DOUBLE,0,MPI_COMM_WORLD);
		// Calculate new likelihood & receive new likelihood from other processes
		_recvd = Vector<bool>(_ntasks,false);
		_recvd[0] = true;
		((ContinuousRV*)_target[0])->propose(x_prime);
		mydouble new_likelihood = _mcmc->update_likelihood();
		// Log (if necessary)
		_mcmc->record_proposal();
		double msg1[2];
		for(i=1;i<_ntasks;i++) {
			// Receive a message from any source with correct handshake
			MPI_Recv(&msg1,2,MPI_DOUBLE,MPI_ANY_SOURCE,_handshake,MPI_COMM_WORLD,&_mpi_status);
			const int source = _mpi_status.MPI_SOURCE;
			// Check message not already received from that source
			if(_recvd[source]) {
				stringstream errTxt;
				errTxt << "MPILogItUniformProposal::go(): handshake " << _handshake << ".\nAlready received message 1 from source " << source;
				error(errTxt.str().c_str());
			}
			_recvd[source] = true;
			// Type mydouble sent as a vector of 2 doubles, the log-likelihood and a boolean to indicate if zero
			mydouble new_likelihood_element;
			if((bool)msg1[1]) new_likelihood_element.setzero();
			else new_likelihood_element.setlog(msg1[0]);
			// Update the new likelihood
			new_likelihood *= new_likelihood_element;
		}
		// Decide whether to accept
		_mcmc->set_alpha(new_likelihood / old_likelihood * hastings);
		bool _accept = (0 <= _mcmc->alpha().LOG() || _mcmc->ran()->U() < _mcmc->alpha().todouble());
		_mcmc->set_accept(_accept);
		// Send instruction whether to accept
		int iaccept = (int)_accept;
		MPI_Bcast(&iaccept,1,MPI_INT,0,MPI_COMM_WORLD);
		// Implement acceptance or rejection
		if(_accept) {
			((ContinuousRV*)_target[0])->accept();
		}
		else {
			_mcmc->revert_likelihood();
			((ContinuousRV*)_target[0])->revert();
		}
	}
	else { // slave
		// Send handshake, old likelihood and parameter value
		mydouble old_likelihood = _mcmc->likelihood();
		const double x = ((ContinuousRV*)_target[0])->get_double();
		double msg0[3] = {old_likelihood.LOG(), (double)old_likelihood.iszero(), x};
		MPI_Send(&msg0,3,MPI_DOUBLE,0,_handshake,MPI_COMM_WORLD);
		// Receive proposal
		double x_prime;
		//MPI_Recv(&xprime,1,MPI_DOUBLE,0,_handshake,MPI_COMM_WORLD,_mpi_status);
		MPI_Bcast(&x_prime,1,MPI_DOUBLE,0,MPI_COMM_WORLD);
		// Calculate new likelihood
		((ContinuousRV*)_target[0])->propose(x_prime);
		mydouble new_likelihood = _mcmc->update_likelihood();
		// Log (if necessary)
		_mcmc->record_proposal();
		// Send new likelihood
		double msg1[2] = {new_likelihood.LOG(), (double)new_likelihood.iszero()};
		MPI_Send(&msg1,2,MPI_DOUBLE,0,_handshake,MPI_COMM_WORLD);
		// Receive instruction whether to accept
		int iaccept;
		MPI_Bcast(&iaccept,1,MPI_INT,0,MPI_COMM_WORLD);
		bool accept = (bool)iaccept;
		// Accept or reject
		_mcmc->set_alpha(new_likelihood/old_likelihood);
		_mcmc->set_accept(accept);
		if(accept) {
			((ContinuousRV*)_target[0])->accept();
		}
		else {
			_mcmc->revert_likelihood();
			((ContinuousRV*)_target[0])->revert();
		}
	}
}

MPIAdaptiveMetropolis::MPIAdaptiveMetropolis(MCMC* mcmc, vector< string > &target, const double weight, const int handshake, const double epsilon, Matrix<double> &C0, const int t0, const double denom) : 
MCMC_move(mcmc,target,weight,"MPIAdaptiveMetropolis"), _handshake(handshake), _master(MPI_taskid==0),
_ntasks(MPI_ntasks), _recvd(Vector<bool>(MPI_ntasks,false)),
_epsilon(epsilon), _C0(C0), _t(0), _t0(t0), _denom(denom), _n_cholesky_fail(0) {
	// Check the number of variables
	_d = _target.size();
	_sd = 2.4*2.4/(double)_d;
	if(!(_C0.nrows()==_C0.ncols())) error("MPIAdaptiveMetropolis: C0 must be a square matrix");
	if(!(_C0.nrows()==_d)) error("MPIAdaptiveMetropolis: number of targets does not match size of C0");
	if(!(_epsilon>=0 && _epsilon<=1)) error("MPIAdaptiveMetropolis: epsilon must have range 0-1");
	if(!(_denom>=0)) error("MPIAdaptiveMetropolis: denom must be non-negative");
	if(!(_t0>=0)) error("MPIAdaptiveMetropolis: t0 must be non-negative");
	// If _denom>0, initialize the empirical covariance matrix with _C0
	if(_denom>0) {
		_C = _C0;
		int i,j;
		for(i=0;i<_d;i++) {
			_C[i][i] += _epsilon;
			for(j=0;j<_d;j++) {
				_C[i][j] *= _sd;
			}
		}
	}
	else {
		_C = Matrix<double>(_d,_d,0);
	}
	_X = Vector<double>(_d,0);
}

MPIAdaptiveMetropolis::~MPIAdaptiveMetropolis() {
	cout << "\n\nAm I called?\n\n" << std::flush;
	if(_n_cholesky_fail>0) {
		stringstream errTxt;
		errTxt << "MPIAdaptiveMetropolis: Cholesky decomposition failed " << _n_cholesky_fail << " times";
		myutils::warning(errTxt.str().c_str());
	}
}

void MPIAdaptiveMetropolis::go() {
	if(_master) {
		// Receive handshake, old log-likelihood and parameter value
		_recvd = Vector<bool>(_ntasks,false);
		_recvd[0] = true;
		mydouble old_likelihood = _mcmc->likelihood();
		Vector<double> x(_d);
		int i;
		for(i=0;i<_d;i++) x[i] = ((ContinuousRV*)_target[i])->get_double();
		int msg_size = 2+_d;
		double msg0[msg_size];
		for(i=1;i<_ntasks;i++) {
			// Receive a message from any source with correct handshake
			MPI_Recv(&msg0,msg_size,MPI_DOUBLE,MPI_ANY_SOURCE,_handshake,MPI_COMM_WORLD,&_mpi_status);
			const int source = _mpi_status.MPI_SOURCE;
			// Check message not already received from that source
			if(_recvd[source]) {
				stringstream errTxt;
				errTxt << "MPIAdaptiveMetropolis::go(): handshake " << _handshake << ".\nAlready received message 0 from source " << source;
				error(errTxt.str().c_str());
			}
			_recvd[source] = true;
			// Check the old parameter value is the same as for the master
			int j;
			for(j=0;j<_d;j++) {
				if(msg0[2+j]!=x[j]) break;
			}
			if(j!=_d) {
				stringstream errTxt;
				errTxt << "MPIAdaptiveMetropolis::go(): handshake " << _handshake << ". Existing value mismatch.\n";
				errTxt << "Task 0 has:";
				for(j=0;j<_d;j++) errTxt << " " << x[j];
				errTxt << "\nTask " << source << " has:";
				for(j=0;j<_d;j++) errTxt << " " << msg0[2+j];
				error(errTxt.str().c_str());
			}
			// Type mydouble sent as a vector of 2 doubles, the log-likelihood and a boolean to indicate if zero
			mydouble old_likelihood_element;
			if((bool)msg0[1]) old_likelihood_element.setzero();
			else old_likelihood_element.setlog(msg0[0]);
			// Update the old likelihood
			old_likelihood *= old_likelihood_element;
		}
		// Make proposal, record Hastings ratio
		Vector<double> x_prime;
		if(_t>_t0) {
			bool cholesky_fail;
			_ran->multivariate_normal(x,_C,x_prime,_temp,_z,&cholesky_fail);
			if(cholesky_fail) {
				warning("MPIAdaptiveMetropolis::go(): Cholesky decomposition failed. Switching to C0.");
				++_n_cholesky_fail;
				_ran->multivariate_normal(x,_C0,x_prime,_temp,_z);
			}
		}
		else {
			_ran->multivariate_normal(x,_C0,x_prime,_temp,_z);
		}
		mydouble hastings = 1;
		// Send proposal
		MPI_Bcast(x_prime.element,_d,MPI_DOUBLE,0,MPI_COMM_WORLD);
		// Calculate new likelihood & receive new likelihood from other processes
		_recvd = Vector<bool>(_ntasks,false);
		_recvd[0] = true;
		for(i=0;i<_d;i++) ((ContinuousRV*)_target[i])->propose(x_prime[i]);
		mydouble new_likelihood = _mcmc->update_likelihood();
		// Log (if necessary)
		_mcmc->record_proposal();
		double msg1[2];
		for(i=1;i<_ntasks;i++) {
			// Receive a message from any source with correct handshake
			MPI_Recv(&msg1,2,MPI_DOUBLE,MPI_ANY_SOURCE,_handshake,MPI_COMM_WORLD,&_mpi_status);
			const int source = _mpi_status.MPI_SOURCE;
			// Check message not already received from that source
			if(_recvd[source]) {
				stringstream errTxt;
				errTxt << "MPIAdaptiveMetropolis::go(): handshake " << _handshake << ".\nAlready received message 1 from source " << source;
				error(errTxt.str().c_str());
			}
			_recvd[source] = true;
			// Type mydouble sent as a vector of 2 doubles, the log-likelihood and a boolean to indicate if zero
			mydouble new_likelihood_element;
			if((bool)msg1[1]) new_likelihood_element.setzero();
			else new_likelihood_element.setlog(msg1[0]);
			// Update the new likelihood
			new_likelihood *= new_likelihood_element;
		}
		// Decide whether to accept
		_mcmc->set_alpha(new_likelihood / old_likelihood * hastings);
		bool _accept = (0 <= _mcmc->alpha().LOG() || _mcmc->ran()->U() < _mcmc->alpha().todouble());
		_mcmc->set_accept(_accept);
		// Send instruction whether to accept
		int iaccept = (int)_accept;
		MPI_Bcast(&iaccept,1,MPI_INT,0,MPI_COMM_WORLD);
		// Implement acceptance or rejection
		if(_accept) {
			for(i=0;i<_d;i++) ((ContinuousRV*)_target[i])->accept();
			update_C(x_prime,_denom+_t+1);
		}
		else {
			_mcmc->revert_likelihood();
			for(i=0;i<_d;i++) ((ContinuousRV*)_target[i])->revert();
			update_C(x,_denom+_t+1);
		}
		++_t;
	}
	else { // slave
		// Send handshake, old likelihood and parameter value
		mydouble old_likelihood = _mcmc->likelihood();
		Vector<double> x(_d);
		int i;
		for(i=0;i<_d;i++) x[i] = ((ContinuousRV*)_target[i])->get_double();
		int msg_size = 2+_d;
		double msg0[msg_size];
		msg0[0] = old_likelihood.LOG();
		msg0[1] = (double)old_likelihood.iszero();
		for(i=0;i<_d;i++) msg0[2+i] = x[i];
		MPI_Send(&msg0,msg_size,MPI_DOUBLE,0,_handshake,MPI_COMM_WORLD);
		// Receive proposal
		Vector<double> x_prime(_d);
		MPI_Bcast(x_prime.element,_d,MPI_DOUBLE,0,MPI_COMM_WORLD);
		// Calculate new likelihood
		for(i=0;i<_d;i++) ((ContinuousRV*)_target[i])->propose(x_prime[i]);
		mydouble new_likelihood = _mcmc->update_likelihood();
		// Log (if necessary)
		_mcmc->record_proposal();
		// Send new likelihood
		double msg1[2] = {new_likelihood.LOG(), (double)new_likelihood.iszero()};
		MPI_Send(&msg1,2,MPI_DOUBLE,0,_handshake,MPI_COMM_WORLD);
		// Receive instruction whether to accept
		int iaccept;
		MPI_Bcast(&iaccept,1,MPI_INT,0,MPI_COMM_WORLD);
		bool accept = (bool)iaccept;
		// Accept or reject
		_mcmc->set_alpha(new_likelihood/old_likelihood);
		_mcmc->set_accept(accept);
		if(accept) {
			for(i=0;i<_d;i++) ((ContinuousRV*)_target[i])->accept();
		}
		else {
			_mcmc->revert_likelihood();
			for(i=0;i<_d;i++) ((ContinuousRV*)_target[i])->revert();
		}
	}
}

void MPIAdaptiveMetropolis::update_C(Vector<double> &X, const double t) {
	/*		Cov(X,Y)	=	E(XY) - E(X)E(Y)
						=	1/n sum_{i=1}^{n} X[i]*Y[i] - 1/n sum_{i=1}^{n} X[i] * 1/n sum_{i=1}^{n} Y[i]

			E[n-1](X)	=	1/(n-1) sum_{i=1}^{n-1} X[i]
			E[n](X)		=	1/n sum_{i=1}^{n} X[i]
						=	(n-1)/n*E[n-1](X) + X[n]/n
	 */
	// First update _X
	Vector<double> _Xprev = _X;
	int i;
	for(i=0;i<_d;i++) {
		_X[i] = (t-1.0)/t*_Xprev[i] + X[i]/t;
	}
	// Now update _C using Eqn 3 of Haario, Saksman and Tamminen (2001)
	int j;
	for(i=0;i<_d;i++) {
		for(j=i;j<_d;j++) {
			_C[i][j] *= (t-1)/t;
			_C[i][j] += _sd/t*(t*_Xprev[i]*_Xprev[j] - (t+1)*_X[i]*_X[j] + X[i]*X[j]);
			if(i==j) {
				_C[i][j] += _sd/t*_epsilon;
			}
			else {
				_C[j][i] = _C[i][j];
			}
		}
	}
}

MPIAdaptiveMetropolisWithinGibbs::MPIAdaptiveMetropolisWithinGibbs(MCMC* mcmc, vector< string > &target, const double weight, const int handshake, const double delta, const int niter, const double ls) : 
MCMC_move(mcmc,target,weight,"MPIAdaptiveMetropolisWithinGibbs"), _handshake(handshake), _master(MPI_taskid==0),
_ntasks(MPI_ntasks), _recvd(Vector<bool>(MPI_ntasks,false)),
_delta(delta), _niter(niter), _ls(ls), _iter(0), _n(0), _naccept(0) {
	// Check the number of variables
	if(_target.size()!=1) error("MPIAdaptiveMetropolisWithinGibbs: exactly one target must be specified");
	if(_delta<=0) error("MPIAdaptiveMetropolisWithinGibbs: delta must be positive");
	if(niter<=0) error("MPIAdaptiveMetropolisWithinGibbs: niter must be positive");
	if(_ls< -12) error("MPIAdaptiveMetropolisWithinGibbs: ls must exceed -12");
	if(_ls> 12) error("MPIAdaptiveMetropolisWithinGibbs: ls must not exceed 12");
	_sd = exp(_ls);
	// Dynamically type-check the variable
	if(!dynamic_cast<ContinuousRV*>(_target[0])) error("MPIAdaptiveMetropolisWithinGibbs: target type incompatible");
}

void MPIAdaptiveMetropolisWithinGibbs::go() {
	if(_master) {
		// Receive handshake, old log-likelihood and parameter value
		_recvd = Vector<bool>(_ntasks,false);
		_recvd[0] = true;
		mydouble old_likelihood = _mcmc->likelihood();
		const double x = ((ContinuousRV*)_target[0])->get_double();
		double msg0[3];
		int i;
		for(i=1;i<_ntasks;i++) {
			// Receive a message from any source with correct handshake
			MPI_Recv(&msg0,3,MPI_DOUBLE,MPI_ANY_SOURCE,_handshake,MPI_COMM_WORLD,&_mpi_status);
			const int source = _mpi_status.MPI_SOURCE;
			// Check message not already received from that source
			if(_recvd[source]) {
				stringstream errTxt;
				errTxt << "MPIAdaptiveMetropolisWithinGibbs::go(): handshake " << _handshake << ".\nAlready received message 0 from source " << source;
				error(errTxt.str().c_str());
			}
			_recvd[source] = true;
			// Check the old parameter value is the same as for the master
			if(msg0[2]!=x) {
				stringstream errTxt;
				errTxt << "MPIAdaptiveMetropolisWithinGibbs::go(): handshake " << _handshake << ". Existing value mismatch.\n";
				errTxt << "Task 0 has " << x << " and task " << source << " has " << msg0[2];
				error(errTxt.str().c_str());
			}
			// Type mydouble sent as a vector of 2 doubles, the log-likelihood and a boolean to indicate if zero
			mydouble old_likelihood_element;
			if((bool)msg0[1]) old_likelihood_element.setzero();
			else old_likelihood_element.setlog(msg0[0]);
			// Update the old likelihood
			old_likelihood *= old_likelihood_element;
		}
		// Make proposal, record Hastings ratio
		double x_prime = x + _ran->normal(0,_sd);
		mydouble hastings = 1;
		// Send proposal
		MPI_Bcast(&x_prime,1,MPI_DOUBLE,0,MPI_COMM_WORLD);
		// Calculate new likelihood & receive new likelihood from other processes
		_recvd = Vector<bool>(_ntasks,false);
		_recvd[0] = true;
		((ContinuousRV*)_target[0])->propose(x_prime);
		mydouble new_likelihood = _mcmc->update_likelihood();
		// Log (if necessary)
		_mcmc->record_proposal();
		double msg1[2];
		for(i=1;i<_ntasks;i++) {
			// Receive a message from any source with correct handshake
			MPI_Recv(&msg1,2,MPI_DOUBLE,MPI_ANY_SOURCE,_handshake,MPI_COMM_WORLD,&_mpi_status);
			const int source = _mpi_status.MPI_SOURCE;
			// Check message not already received from that source
			if(_recvd[source]) {
				stringstream errTxt;
				errTxt << "MPIAdaptiveMetropolisWithinGibbs::go(): handshake " << _handshake << ".\nAlready received message 1 from source " << source;
				error(errTxt.str().c_str());
			}
			_recvd[source] = true;
			// Type mydouble sent as a vector of 2 doubles, the log-likelihood and a boolean to indicate if zero
			mydouble new_likelihood_element;
			if((bool)msg1[1]) new_likelihood_element.setzero();
			else new_likelihood_element.setlog(msg1[0]);
			// Update the new likelihood
			new_likelihood *= new_likelihood_element;
		}
		// Decide whether to accept
		_mcmc->set_alpha(new_likelihood / old_likelihood * hastings);
		bool _accept = (0 <= _mcmc->alpha().LOG() || _mcmc->ran()->U() < _mcmc->alpha().todouble());
		_mcmc->set_accept(_accept);
		// Send instruction whether to accept
		int iaccept = (int)_accept;
		MPI_Bcast(&iaccept,1,MPI_INT,0,MPI_COMM_WORLD);
		// Implement acceptance or rejection
		if(_accept) {
			((ContinuousRV*)_target[0])->accept();
			++_naccept;
		}
		else {
			_mcmc->revert_likelihood();
			((ContinuousRV*)_target[0])->revert();
		}
	}
	else { // slave
		// Send handshake, old likelihood and parameter value
		mydouble old_likelihood = _mcmc->likelihood();
		const double x = ((ContinuousRV*)_target[0])->get_double();
		double msg0[3] = {old_likelihood.LOG(), (double)old_likelihood.iszero(), x};
		MPI_Send(&msg0,3,MPI_DOUBLE,0,_handshake,MPI_COMM_WORLD);
		// Receive proposal
		double x_prime;
		//MPI_Recv(&xprime,1,MPI_DOUBLE,0,_handshake,MPI_COMM_WORLD,_mpi_status);
		MPI_Bcast(&x_prime,1,MPI_DOUBLE,0,MPI_COMM_WORLD);
		// Calculate new likelihood
		((ContinuousRV*)_target[0])->propose(x_prime);
		mydouble new_likelihood = _mcmc->update_likelihood();
		// Log (if necessary)
		_mcmc->record_proposal();
		// Send new likelihood
		double msg1[2] = {new_likelihood.LOG(), (double)new_likelihood.iszero()};
		MPI_Send(&msg1,2,MPI_DOUBLE,0,_handshake,MPI_COMM_WORLD);
		// Receive instruction whether to accept
		int iaccept;
		MPI_Bcast(&iaccept,1,MPI_INT,0,MPI_COMM_WORLD);
		bool accept = (bool)iaccept;
		// Accept or reject
		_mcmc->set_alpha(new_likelihood/old_likelihood);
		_mcmc->set_accept(accept);
		if(accept) {
			((ContinuousRV*)_target[0])->accept();
			++_naccept;
		}
		else {
			_mcmc->revert_likelihood();
			((ContinuousRV*)_target[0])->revert();
		}
	}
	// Increment the iteration number of this batch
	++_iter;
	// If the requisite number of iterations per batch is passed, update _ls and _sd
	if(_iter % _niter == 0) {
		// Increment the number of batches
		++_n;
		// Update _delta: _delta gets smaller as the number of batches increases
		_delta = myutils::MIN(_delta,pow((double)_n,-0.5));
		// Calculate the acceptance ratio for the most recent batch
		const double aratio = (double)_naccept/(double)_niter;
		// If too big, increase the variance of the proposal distribution
		if(aratio > 0.44) {
			_ls += _delta;
			if(_ls > 12) _ls = 12;
		}
		// If too small, decrease the variance of the proposal distribution
		else if(aratio < 0.44) {
			_ls -= _delta;
			if(_ls < -12) _ls = -12;
		}
		_sd = exp(_ls);
		_iter = 0;
		_naccept = 0;
	}
}

MPILogNormalProposal::MPILogNormalProposal(MCMC* mcmc, vector< string > &target, const double weight, const int handshake, const double sd) : MCMC_move(mcmc,target,weight,"MPILogNormalProposal"), _sd(sd), _handshake(handshake), _master(MPI_taskid==0), _ntasks(MPI_ntasks), _recvd(Vector<bool>(MPI_ntasks,false)) {
	if(_target.size()!=1) error("MPILogNormalProposal: target vector must have 1 element");
	if(_sd<=0.0) error("MPILogNormalProposal: sd must be positive");
	// Dynamically type-check the variable
	if(!dynamic_cast<ContinuousRV*>(_target[0])) error("MPILogNormalProposal: target type incompatible");
}

void MPILogNormalProposal::go() {
	if(_master) {
		// Receive handshake, old log-likelihood and parameter value
		_recvd = Vector<bool>(_ntasks,false);
		_recvd[0] = true;
		mydouble old_likelihood = _mcmc->likelihood();
		const double x = ((ContinuousRV*)_target[0])->get_double();
		double msg0[3];
		int i;
		for(i=1;i<_ntasks;i++) {
			// Receive a message from any source with correct handshake
			MPI_Recv(&msg0,3,MPI_DOUBLE,MPI_ANY_SOURCE,_handshake,MPI_COMM_WORLD,&_mpi_status);
			const int source = _mpi_status.MPI_SOURCE;
			// Check message not already received from that source
			if(_recvd[source]) {
				stringstream errTxt;
				errTxt << "MPILogNormalProposal::go(): handshake " << _handshake << ".\nAlready received message 0 from source " << source;
				error(errTxt.str().c_str());
			}
			_recvd[source] = true;
			// Check the old parameter value is the same as for the master
			if(msg0[2]!=x) {
				stringstream errTxt;
				errTxt << "MPILogNormalProposal::go(): handshake " << _handshake << ". Existing value mismatch.\n";
				errTxt << "Task 0 has " << x << " and task " << source << " has " << msg0[2];
				error(errTxt.str().c_str());
			}
			// Type mydouble sent as a vector of 2 doubles, the log-likelihood and a boolean to indicate if zero
			mydouble old_likelihood_element;
			if((bool)msg0[1]) old_likelihood_element.setzero();
			else old_likelihood_element.setlog(msg0[0]);
			// Update the old likelihood
			old_likelihood *= old_likelihood_element;
		}
		// Make proposal, record Hastings ratio
		const double U = _ran->normal(0,_sd);
		double x_prime = x * exp(U);
		mydouble hastings;
		hastings.setlog(U);
		// Send proposal
		MPI_Bcast(&x_prime,1,MPI_DOUBLE,0,MPI_COMM_WORLD);
		// Calculate new likelihood & receive new likelihood from other processes
		_recvd = Vector<bool>(_ntasks,false);
		_recvd[0] = true;
		((ContinuousRV*)_target[0])->propose(x_prime);
		mydouble new_likelihood = _mcmc->update_likelihood();
		// Log (if necessary)
		_mcmc->record_proposal();
		double msg1[2];
		for(i=1;i<_ntasks;i++) {
			// Receive a message from any source with correct handshake
			MPI_Recv(&msg1,2,MPI_DOUBLE,MPI_ANY_SOURCE,_handshake,MPI_COMM_WORLD,&_mpi_status);
			const int source = _mpi_status.MPI_SOURCE;
			// Check message not already received from that source
			if(_recvd[source]) {
				stringstream errTxt;
				errTxt << "MPILogNormalProposal::go(): handshake " << _handshake << ".\nAlready received message 1 from source " << source;
				error(errTxt.str().c_str());
			}
			_recvd[source] = true;
			// Type mydouble sent as a vector of 2 doubles, the log-likelihood and a boolean to indicate if zero
			mydouble new_likelihood_element;
			if((bool)msg1[1]) new_likelihood_element.setzero();
			else new_likelihood_element.setlog(msg1[0]);
			// Update the new likelihood
			new_likelihood *= new_likelihood_element;
		}
		// Decide whether to accept
		_mcmc->set_alpha(new_likelihood / old_likelihood * hastings);
		bool _accept = (0 <= _mcmc->alpha().LOG() || _mcmc->ran()->U() < _mcmc->alpha().todouble());
		_mcmc->set_accept(_accept);
		// Send instruction whether to accept
		int iaccept = (int)_accept;
		MPI_Bcast(&iaccept,1,MPI_INT,0,MPI_COMM_WORLD);
		// Implement acceptance or rejection
		if(_accept) {
			((ContinuousRV*)_target[0])->accept();
		}
		else {
			_mcmc->revert_likelihood();
			((ContinuousRV*)_target[0])->revert();
		}
	}
	else { // slave
		// Send handshake, old likelihood and parameter value
		mydouble old_likelihood = _mcmc->likelihood();
		const double x = ((ContinuousRV*)_target[0])->get_double();
		double msg0[3] = {old_likelihood.LOG(), (double)old_likelihood.iszero(), x};
		MPI_Send(&msg0,3,MPI_DOUBLE,0,_handshake,MPI_COMM_WORLD);
		// Receive proposal
		double x_prime;
		//MPI_Recv(&xprime,1,MPI_DOUBLE,0,_handshake,MPI_COMM_WORLD,_mpi_status);
		MPI_Bcast(&x_prime,1,MPI_DOUBLE,0,MPI_COMM_WORLD);
		// Calculate new likelihood
		((ContinuousRV*)_target[0])->propose(x_prime);
		mydouble new_likelihood = _mcmc->update_likelihood();
		// Log (if necessary)
		_mcmc->record_proposal();
		// Send new likelihood
		double msg1[2] = {new_likelihood.LOG(), (double)new_likelihood.iszero()};
		MPI_Send(&msg1,2,MPI_DOUBLE,0,_handshake,MPI_COMM_WORLD);
		// Receive instruction whether to accept
		int iaccept;
		MPI_Bcast(&iaccept,1,MPI_INT,0,MPI_COMM_WORLD);
		bool accept = (bool)iaccept;
		// Accept or reject
		_mcmc->set_alpha(new_likelihood/old_likelihood);
		_mcmc->set_accept(accept);
		if(accept) {
			((ContinuousRV*)_target[0])->accept();
		}
		else {
			_mcmc->revert_likelihood();
			((ContinuousRV*)_target[0])->revert();
		}
	}
}

MPILogNormalSyncProposal::MPILogNormalSyncProposal(MCMC* mcmc, vector< string > &target, const double weight, const int handshake, const double sd) : MCMC_move(mcmc,target,weight,"MPILogNormalSyncProposal"), _sd(sd), _handshake(handshake), _master(MPI_taskid==0), _ntasks(MPI_ntasks), _recvd(Vector<bool>(MPI_ntasks,false)), _d(target.size()) {
	if(_d==0) error("MPILogNormalSyncProposal: target vector must have at least 1 element");
	if(_sd<=0.0) error("MPILogNormalSyncProposal: sd must be positive");
	// Dynamically type-check the variable
	int i;
	for(i=0;i<_d;i++) {
		if(!dynamic_cast<ContinuousRV*>(_target[i])) error("MPILogNormalSyncProposal: target type incompatible");
	}
}

void MPILogNormalSyncProposal::go() {
	if(_master) {
		// Receive handshake, old log-likelihood and parameter value
		_recvd = Vector<bool>(_ntasks,false);
		_recvd[0] = true;
		mydouble old_likelihood = _mcmc->likelihood();
		Vector<double> x(_d);
		int i;
		for(i=0;i<_d;i++) x[i] = ((ContinuousRV*)_target[i])->get_double();
		int msg_size = 2+_d;
		double msg0[msg_size];
		for(i=1;i<_ntasks;i++) {
			// Receive a message from any source with correct handshake
			MPI_Recv(&msg0,msg_size,MPI_DOUBLE,MPI_ANY_SOURCE,_handshake,MPI_COMM_WORLD,&_mpi_status);
			const int source = _mpi_status.MPI_SOURCE;
			// Check message not already received from that source
			if(_recvd[source]) {
				stringstream errTxt;
				errTxt << "MPILogNormalSyncProposal::go(): handshake " << _handshake << ".\nAlready received message 0 from source " << source;
				error(errTxt.str().c_str());
			}
			_recvd[source] = true;
			// Check the old parameter value is the same as for the master
			int j;
			for(j=0;j<_d;j++) {
				if(msg0[2+j]!=x[j]) break;
			}
			if(j!=_d) {
				stringstream errTxt;
				errTxt << "MPILogNormalSyncProposal::go(): handshake " << _handshake << ". Existing value mismatch.\n";
				errTxt << "Task 0 has:";
				for(j=0;j<_d;j++) errTxt << " " << x[j];
				errTxt << "\nTask " << source << " has:";
				for(j=0;j<_d;j++) errTxt << " " << msg0[2+j];
				error(errTxt.str().c_str());
			}
			// Type mydouble sent as a vector of 2 doubles, the log-likelihood and a boolean to indicate if zero
			mydouble old_likelihood_element;
			if((bool)msg0[1]) old_likelihood_element.setzero();
			else old_likelihood_element.setlog(msg0[0]);
			// Update the old likelihood
			old_likelihood *= old_likelihood_element;
		}
		// Make proposal, record Hastings ratio
		Vector<double> x_prime;
		const double U = _ran->normal(0,_sd);
		for(i=0;i<_d;i++) x_prime[i] = x[i] * exp(U);
		// !!!!!!!!!! IS THIS HASTINGS RATIO CORRECT? !!!!!!!!!!!
		mydouble hastings;
		hastings.setlog(U);
		// Send proposal
		MPI_Bcast(x_prime.element,_d,MPI_DOUBLE,0,MPI_COMM_WORLD);
		// Calculate new likelihood & receive new likelihood from other processes
		_recvd = Vector<bool>(_ntasks,false);
		_recvd[0] = true;
		for(i=0;i<_d;i++) ((ContinuousRV*)_target[i])->propose(x_prime[i]);
		mydouble new_likelihood = _mcmc->update_likelihood();
		// Log (if necessary)
		_mcmc->record_proposal();
		double msg1[2];
		for(i=1;i<_ntasks;i++) {
			// Receive a message from any source with correct handshake
			MPI_Recv(&msg1,2,MPI_DOUBLE,MPI_ANY_SOURCE,_handshake,MPI_COMM_WORLD,&_mpi_status);
			const int source = _mpi_status.MPI_SOURCE;
			// Check message not already received from that source
			if(_recvd[source]) {
				stringstream errTxt;
				errTxt << "MPILogNormalSyncProposal::go(): handshake " << _handshake << ".\nAlready received message 1 from source " << source;
				error(errTxt.str().c_str());
			}
			_recvd[source] = true;
			// Type mydouble sent as a vector of 2 doubles, the log-likelihood and a boolean to indicate if zero
			mydouble new_likelihood_element;
			if((bool)msg1[1]) new_likelihood_element.setzero();
			else new_likelihood_element.setlog(msg1[0]);
			// Update the new likelihood
			new_likelihood *= new_likelihood_element;
		}
		// Decide whether to accept
		_mcmc->set_alpha(new_likelihood / old_likelihood * hastings);
		bool _accept = (0 <= _mcmc->alpha().LOG() || _mcmc->ran()->U() < _mcmc->alpha().todouble());
		_mcmc->set_accept(_accept);
		// Send instruction whether to accept
		int iaccept = (int)_accept;
		MPI_Bcast(&iaccept,1,MPI_INT,0,MPI_COMM_WORLD);
		// Implement acceptance or rejection
		if(_accept) {
			for(i=0;i<_d;i++) ((ContinuousRV*)_target[i])->accept();
		}
		else {
			_mcmc->revert_likelihood();
			for(i=0;i<_d;i++) ((ContinuousRV*)_target[i])->revert();
		}
	}
	else { // slave
		// Send handshake, old likelihood and parameter value
		mydouble old_likelihood = _mcmc->likelihood();
		Vector<double> x(_d);
		int i;
		for(i=0;i<_d;i++) x[i] = ((ContinuousRV*)_target[i])->get_double();
		int msg_size = 2+_d;
		double msg0[msg_size];
		msg0[0] = old_likelihood.LOG();
		msg0[1] = (double)old_likelihood.iszero();
		for(i=0;i<_d;i++) msg0[2+i] = x[i];
		MPI_Send(&msg0,msg_size,MPI_DOUBLE,0,_handshake,MPI_COMM_WORLD);
		// Receive proposal
		Vector<double> x_prime(_d);
		MPI_Bcast(x_prime.element,_d,MPI_DOUBLE,0,MPI_COMM_WORLD);
		// Calculate new likelihood
		for(i=0;i<_d;i++) ((ContinuousRV*)_target[i])->propose(x_prime[i]);
		mydouble new_likelihood = _mcmc->update_likelihood();
		// Log (if necessary)
		_mcmc->record_proposal();
		// Send new likelihood
		double msg1[2] = {new_likelihood.LOG(), (double)new_likelihood.iszero()};
		MPI_Send(&msg1,2,MPI_DOUBLE,0,_handshake,MPI_COMM_WORLD);
		// Receive instruction whether to accept
		int iaccept;
		MPI_Bcast(&iaccept,1,MPI_INT,0,MPI_COMM_WORLD);
		bool accept = (bool)iaccept;
		// Accept or reject
		_mcmc->set_alpha(new_likelihood/old_likelihood);
		_mcmc->set_accept(accept);
		if(accept) {
			for(i=0;i<_d;i++) ((ContinuousRV*)_target[i])->accept();
		}
		else {
			_mcmc->revert_likelihood();
			for(i=0;i<_d;i++) ((ContinuousRV*)_target[i])->revert();
		}
	}
}

MPISwitchProposal::MPISwitchProposal(MCMC* mcmc, vector< string > &target, const double weight, const int handshake) : MCMC_move(mcmc,target,weight,"MPISwitchProposal"), _handshake(handshake), _master(MPI_taskid==0), _ntasks(MPI_ntasks), _recvd(Vector<bool>(MPI_ntasks,false)), _d(target.size()) {
	if(_d<2) error("MPISwitchProposal: target vector must have at least 2 elements");
	// Dynamically type-check the variable
	int i;
	for(i=0;i<_d;i++) {
		if(!dynamic_cast<ContinuousRV*>(_target[i])) error("MPISwitchProposal: target type incompatible");
	}
}

void MPISwitchProposal::go() {
	if(_master) {
		// Receive handshake, old log-likelihood and parameter value
		_recvd = Vector<bool>(_ntasks,false);
		_recvd[0] = true;
		mydouble old_likelihood = _mcmc->likelihood();
		Vector<double> x(_d);
		int i;
		for(i=0;i<_d;i++) x[i] = ((ContinuousRV*)_target[i])->get_double();
		int msg_size = 2+_d;
		double msg0[msg_size];
		for(i=1;i<_ntasks;i++) {
			// Receive a message from any source with correct handshake
			MPI_Recv(&msg0,msg_size,MPI_DOUBLE,MPI_ANY_SOURCE,_handshake,MPI_COMM_WORLD,&_mpi_status);
			const int source = _mpi_status.MPI_SOURCE;
			// Check message not already received from that source
			if(_recvd[source]) {
				stringstream errTxt;
				errTxt << "MPISwitchProposal::go(): handshake " << _handshake << ".\nAlready received message 0 from source " << source;
				error(errTxt.str().c_str());
			}
			_recvd[source] = true;
			// Check the old parameter value is the same as for the master
			int j;
			for(j=0;j<_d;j++) {
				if(msg0[2+j]!=x[j]) break;
			}
			if(j!=_d) {
				stringstream errTxt;
				errTxt << "MPISwitchProposal::go(): handshake " << _handshake << ". Existing value mismatch.\n";
				errTxt << "Task 0 has:";
				for(j=0;j<_d;j++) errTxt << " " << x[j];
				errTxt << "\nTask " << source << " has:";
				for(j=0;j<_d;j++) errTxt << " " << msg0[2+j];
				error(errTxt.str().c_str());
			}
			// Type mydouble sent as a vector of 2 doubles, the log-likelihood and a boolean to indicate if zero
			mydouble old_likelihood_element;
			if((bool)msg0[1]) old_likelihood_element.setzero();
			else old_likelihood_element.setlog(msg0[0]);
			// Update the old likelihood
			old_likelihood *= old_likelihood_element;
		}
		// Make proposal, record Hastings ratio
		Vector<double> x_prime(x);
		const int sw1 = _ran->discrete(0,_d-1);
		int sw2 = _ran->discrete(0,_d-2);
		if(sw2==sw1) sw2 = _d-1;
		x_prime[sw1] = x[sw2];
		x_prime[sw2] = x[sw1];
		mydouble hastings = 1;
		// Send proposal
		MPI_Bcast(x_prime.element,_d,MPI_DOUBLE,0,MPI_COMM_WORLD);
		// Calculate new likelihood & receive new likelihood from other processes
		_recvd = Vector<bool>(_ntasks,false);
		_recvd[0] = true;
		for(i=0;i<_d;i++) ((ContinuousRV*)_target[i])->propose(x_prime[i]);
		mydouble new_likelihood = _mcmc->update_likelihood();
		// Log (if necessary)
		_mcmc->record_proposal();
		double msg1[2];
		for(i=1;i<_ntasks;i++) {
			// Receive a message from any source with correct handshake
			MPI_Recv(&msg1,2,MPI_DOUBLE,MPI_ANY_SOURCE,_handshake,MPI_COMM_WORLD,&_mpi_status);
			const int source = _mpi_status.MPI_SOURCE;
			// Check message not already received from that source
			if(_recvd[source]) {
				stringstream errTxt;
				errTxt << "MPISwitchProposal::go(): handshake " << _handshake << ".\nAlready received message 1 from source " << source;
				error(errTxt.str().c_str());
			}
			_recvd[source] = true;
			// Type mydouble sent as a vector of 2 doubles, the log-likelihood and a boolean to indicate if zero
			mydouble new_likelihood_element;
			if((bool)msg1[1]) new_likelihood_element.setzero();
			else new_likelihood_element.setlog(msg1[0]);
			// Update the new likelihood
			new_likelihood *= new_likelihood_element;
		}
		// Decide whether to accept
		_mcmc->set_alpha(new_likelihood / old_likelihood * hastings);
		bool _accept = (0 <= _mcmc->alpha().LOG() || _mcmc->ran()->U() < _mcmc->alpha().todouble());
		_mcmc->set_accept(_accept);
		// Send instruction whether to accept
		int iaccept = (int)_accept;
		MPI_Bcast(&iaccept,1,MPI_INT,0,MPI_COMM_WORLD);
		// Implement acceptance or rejection
		if(_accept) {
			for(i=0;i<_d;i++) ((ContinuousRV*)_target[i])->accept();
		}
		else {
			_mcmc->revert_likelihood();
			for(i=0;i<_d;i++) ((ContinuousRV*)_target[i])->revert();
		}
	}
	else { // slave
		// Send handshake, old likelihood and parameter value
		mydouble old_likelihood = _mcmc->likelihood();
		Vector<double> x(_d);
		int i;
		for(i=0;i<_d;i++) x[i] = ((ContinuousRV*)_target[i])->get_double();
		int msg_size = 2+_d;
		double msg0[msg_size];
		msg0[0] = old_likelihood.LOG();
		msg0[1] = (double)old_likelihood.iszero();
		for(i=0;i<_d;i++) msg0[2+i] = x[i];
		MPI_Send(&msg0,msg_size,MPI_DOUBLE,0,_handshake,MPI_COMM_WORLD);
		// Receive proposal
		Vector<double> x_prime(_d);
		MPI_Bcast(x_prime.element,_d,MPI_DOUBLE,0,MPI_COMM_WORLD);
		// Calculate new likelihood
		for(i=0;i<_d;i++) ((ContinuousRV*)_target[i])->propose(x_prime[i]);
		mydouble new_likelihood = _mcmc->update_likelihood();
		// Log (if necessary)
		_mcmc->record_proposal();
		// Send new likelihood
		double msg1[2] = {new_likelihood.LOG(), (double)new_likelihood.iszero()};
		MPI_Send(&msg1,2,MPI_DOUBLE,0,_handshake,MPI_COMM_WORLD);
		// Receive instruction whether to accept
		int iaccept;
		MPI_Bcast(&iaccept,1,MPI_INT,0,MPI_COMM_WORLD);
		bool accept = (bool)iaccept;
		// Accept or reject
		_mcmc->set_alpha(new_likelihood/old_likelihood);
		_mcmc->set_accept(accept);
		if(accept) {
			for(i=0;i<_d;i++) ((ContinuousRV*)_target[i])->accept();
		}
		else {
			_mcmc->revert_likelihood();
			for(i=0;i<_d;i++) ((ContinuousRV*)_target[i])->revert();
		}
	}
}
	
} // namespace gcat

