/*  Copyright 2012 Daniel Wilson.
 *
 *  MCMC.h
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
#ifndef _MCMC_H_
#define _MCMC_H_
#include <DAG/DAG.h>
#include <vector>
#include <random.h>
#include <fstream>
#include <ostream>
#include <matrix.h>

using std::vector;
using myutils::Random;
using std::ostream;
using std::ofstream;
using myutils::Matrix;

namespace gcat {

// Forward declaration
class MCMC;

class MCMC_move {
protected:
	std::string _type;
	// Pointer to owning MCMC object
	MCMC* _mcmc;
	// For shortcuts...
	DAG* _dag;
	Random* _ran;
	// Target variables
	vector< RandomVariable* > _target;
public:
	// Constructor
	MCMC_move(MCMC* mcmc, vector< std::string > &target, const double weight, std::string type="MCMC_move");
	// Destructor
	virtual ~MCMC_move() {};
	// Implement
	virtual void go() = 0;
	// Move type
	std::string type() const;
	// Targets
	vector<std::string> targets() const;
};

class MCMC_log {
protected:
	DAG* _dag;
	MCMC* _mcmc;
	// Filename (if any)
	std::string _filename;
	// Burn-in defined as the minimum burn-in time (thinning may lengthen it)
	int _burnin;
	// Thinning interval
	int _thinning;
	// Pointer to ostream for the log
	ostream* _fout;
	// Local ofstream which is to be deleted if created
	ofstream* __fout;
	// Number of parameters to log
	int _n_params;
	// List of parameters to log
	vector< Variable* > _parameter;
	// Number of parameters to log the log-likelihood
	int _n_params_loglik;
	// List of parameters to log the log-likelihood
	vector< RandomVariable* > _parameter_loglik;
	// Format variables
	bool _record_iter;
	std::string _sep;
	bool _record_move;
	bool _record_proposal;
public:
	// Constructor
	MCMC_log(DAG* dag, std::string filename, const int burnin, const int thinning, bool record_iter=true, bool record_move=false, bool record_proposal=false, std::string sep="\t");
	// Constructor
	MCMC_log(DAG* dag, ostream* fout, const int burnin, const int thinning, bool record_iter=true, bool record_move=false, bool record_proposal=false, std::string sep="\t");
	// Destructor
	virtual ~MCMC_log();
	// Add a parameter to the log
	void add_parameter(std::string var);
	// Add a parameter to the log
	void add_parameter(Variable* var);
	// Add a parameter to the log
	void add_loglik(std::string var);
	// Add a parameter to the log
	void add_loglik(Variable* var);
	// Log the headings
	void log_header();
	// Update log
	void log(const int iter);
	// Do I record proposals?
	bool record_proposal() const;
};

// To replace the member variable
extern Random _ran;

class MCMC : public InferenceTechnique {
protected:
	// Pointer to DAG
	DAG* _dag;
	
	// Number of move types
	int _n_moves;
	// Vector of MCMC moves
	vector< MCMC_move* > _move;
	// Weight for each move
	vector< double > _weight;
	// Cumulative proposal probability for each move
	vector< double > _cum_prob;

	// Vector of pointers to MCMC log objects
	vector< MCMC_log* > _log;

	// Number of iterations to perform
	int _niter;
	// Flag: output progress to screen?
	bool _coutput;
	// Screen update interval in seconds
	double _coutput_interval;
	// Random or systematic sweep?
	bool _random_sweep;
	// Flag: monitor performance?
	bool _monitor_performance;
	// Performance monitoring interval
	int _performance_interval;

	// Current likelihood and acceptance ratio
	mydouble _likelihood, _alpha, _old_likelihood;
	// Was last proposal accepted?
	bool _accept;
	// Last move
	int _last_move;
	// Remember the iteration
	int iter;
	// Systematic sweep increment
	double _sys_inc;
	// Record of performance for each move
	Matrix< int > _npro, _nacc;

public:
	// Constructor
	MCMC(DAG* dag, const int seed, const int niter, const double coutput_interval, const bool random_sweep=true, const int performance_interval=0);
	// Destructor
	virtual ~MCMC();
	// Add a move
	void add_move(MCMC_move* move, const double weight);
	// Add a log
	void add_log(MCMC_log* log);
	// Go! Implements pure virtual function in base class
	void perform_inference();
	// Pointer to ran
	Random* get_ran();
	// Last likelihood, alpha and acceptance
	mydouble likelihood() const;
	void set_alpha(const mydouble& a);
	mydouble alpha() const;
	void set_accept(const bool a);
	bool accept() const;
	std::string last_move() const;
	vector<std::string> last_targets() const;
	// Pointer to DAG
	DAG* dag();
	// Update the likelihood
	mydouble update_likelihood();
	// Revert the likelihood (if a proposal is rejected)
	mydouble revert_likelihood();
	// Record the proposal
	void record_proposal();
	// Random number generator
	Random* ran();
	// Record performance for the last move
	void record_performance();
protected:
	// Propose a move
	void propose();
	// Propose a move in a systematic sweep
	void propose_systematic();
	// Propose a specific move
	void propose(const int i);
	// Normalize weights
	void normalize_weights();
};
	
} // namespace gcat


#endif //_MCMC_H_