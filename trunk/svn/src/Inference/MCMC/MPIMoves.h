/*  Copyright 2012 Daniel Wilson.
 *
 *  MPIMoves.h
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
#ifndef _MPI_MCMC_MOVES_H_
#define _MPI_MCMC_MOVES_H_
#include <Inference/MCMC/MCMC.h>
#include <mpi.h>
#include <vector.h>

using myutils::Vector;
using myutils::warning;

namespace gcat {

class MPIUniformProposal : public MCMC_move {
protected:
	double _half_width;
	bool _master;
	int _handshake;
	MPI_Status _mpi_status;
	int _ntasks;
	Vector<bool> _recvd;
public:
	// Constructor
	MPIUniformProposal(MCMC* mcmc, vector< string > &target, const double weight, const int handshake, const double half_width=1.0);
	// Go!!!
	void go();
	// Return Hastings ratio
	//mydouble propose();
	// Implement accept()
	//void accept();
	// Implement reject()
	//void reject();
};

class MPILogUniformProposal : public MCMC_move {
protected:
	double _half_width;
	bool _master;
	int _handshake;
	MPI_Status _mpi_status;
	int _ntasks;
	Vector<bool> _recvd;
public:
	// Constructor
	MPILogUniformProposal(MCMC* mcmc, vector< string > &target, const double weight, const int handshake, const double half_width=1.0);
	// Go!!!
	void go();
	// Return Hastings ratio
	//mydouble propose();
	// Implement accept()
	//void accept();
	// Implement reject()
	//void reject();
};

class MPILogItUniformProposal : public MCMC_move {
protected:
	double _half_width;
	bool _master;
	int _handshake;
	MPI_Status _mpi_status;
	int _ntasks;
	Vector<bool> _recvd;
public:
	// Constructor
	MPILogItUniformProposal(MCMC* mcmc, vector< string > &target, const double weight, const int handshake, const double half_width=1.0);
	// Go!!!
	void go();
	// Return Hastings ratio
	//mydouble propose();
	// Implement accept()
	//void accept();
	// Implement reject()
	//void reject();
};

class mustDestruct {
	int _x;
	int *_y;
public:
	mustDestruct(const int x=0) : _x(x) {
		cout << "Constructing!\n";
		_y = new int(101);
	}
	~mustDestruct() {
		cout << "\n\n\n\n\nDestruct!!!!\n\n\n\n\n" << std::flush;
		delete _y;
	}
};

// Implements the method of Haario, Saksman and Tamminen (2001) Bernoulli 7: 223-242.
class MPIAdaptiveMetropolis : public MCMC_move {
protected:
	//mustDestruct _md;
	// Variables used in the calculation of the proposal distribution
	// Number of variables
	int _d;
	// Equal to 2.4^2/d
	double _sd;
	// The weight of the identity matrix in making proposals, avoids degeneration of _C
	double _epsilon;
	// Initial covariance matrix for multivariate normal proposals
	Matrix<double> _C0;
	// Current covariance matrix for multivariate normal proposals
	Matrix<double> _C;
	// Empirical mean of the variables so far
	Vector<double> _X;
	// Number of updates to _C. Set this initially to >0 to influence _C with _C0 (not part of official method)
	double _denom;
	// Current iteration
	int _t;
	// Number of iterations at which to begin proposals using _C instead of _C0
	int _t0;

	// Temporary variables used in multivariate normal generation
	Matrix<double> _temp;
	Vector<double> _z;
	int _n_cholesky_fail;
	
	// MPI variables
	bool _master;
	int _handshake;
	MPI_Status _mpi_status;
	int _ntasks;
	Vector<bool> _recvd;
public:
	// Constructor
	MPIAdaptiveMetropolis(MCMC* mcmc, vector< string > &target, const double weight, const int handshake, const double epsilon, Matrix<double> &C0, const int t0, const double denom);
	// Destructor
	virtual ~MPIAdaptiveMetropolis();
	// Go!!!
	void go();
	// Return Hastings ratio
	//mydouble propose();
	// Implement accept()
	//void accept();
	// Implement reject()
	//void reject();
private:
	// Use a recursion to update the 
	void update_C(Vector<double> &X, const double t);
};

// Implements the method of Roberts and Rosenthal (2008) Journal of Computational and Graphical Statistics 18: 349-367.
class MPIAdaptiveMetropolisWithinGibbs : public MCMC_move {
protected:
	// Iteration number (for this specific move)
	int _iter;
	// Number of iterations per batch
	int _niter;
	// Batch number
	int _n;
	// Current increment (initially must be less than 1)
	double _delta;
	// Current proposal log standard deviation
	double _ls;
	// Current proposal standard deviation
	double _sd;
	// Number of proposals accepted this batch
	int _naccept;

	// MPI variables
	bool _master;
	int _handshake;
	MPI_Status _mpi_status;
	int _ntasks;
	Vector<bool> _recvd;
public:
	// Constructor
	MPIAdaptiveMetropolisWithinGibbs(MCMC* mcmc, vector< string > &target, const double weight, const int handshake, const double delta, const int niter, const double ls);
	// Go!!!
	void go();
	// Return Hastings ratio
	//mydouble propose();
	// Implement accept()
	//void accept();
	// Implement reject()
	//void reject();
};

class MPILogNormalProposal : public MCMC_move {
protected:
	double _sd;
	bool _master;
	int _handshake;
	MPI_Status _mpi_status;
	int _ntasks;
	Vector<bool> _recvd;
public:
	// Constructor
	MPILogNormalProposal(MCMC* mcmc, vector< string > &target, const double weight, const int handshake, const double sd=1.0);
	// Go!!!
	void go();
};

class MPILogNormalSyncProposal : public MCMC_move {
protected:
	int _d;
	double _sd;
	bool _master;
	int _handshake;
	MPI_Status _mpi_status;
	int _ntasks;
	Vector<bool> _recvd;
public:
	// Constructor
	MPILogNormalSyncProposal(MCMC* mcmc, vector< string > &targets, const double weight, const int handshake, const double sd=1.0);
	// Go!!!
	void go();
};

class MPISwitchProposal : public MCMC_move {
protected:
	int _d;
	bool _master;
	int _handshake;
	MPI_Status _mpi_status;
	int _ntasks;
	Vector<bool> _recvd;
public:
	// Constructor
	MPISwitchProposal(MCMC* mcmc, vector< string > &targets, const double weight, const int handshake);
	// Go!!!
	void go();
};
	
} // namespace gcat

#endif //_MPI_MCMC_MOVES_H_


