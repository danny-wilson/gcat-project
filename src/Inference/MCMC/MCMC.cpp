/*  Copyright 2012 Daniel Wilson.
 *
 *  MCMC.cpp
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
#include <Inference/MCMC/MCMC.h>
#include <DAG/Variable.h>
#include <DAG/RandomVariable.h>
#include <myerror.h>
#include <time.h>
#include <iostream>
#include <utils.h>

using myutils::error;
using myutils::Random;
using std::cout;
using std::endl;
using std::flush;

namespace gcat {

MCMC_move::MCMC_move(MCMC* mcmc, vector< string > &target, const double weight, string type) : _mcmc(mcmc), _dag(mcmc->dag()), _ran(mcmc->ran()), _type(type) {
	if(target.size()==0) error("MCMC_move: no targets");
	int i;
	for(i=0;i<target.size();i++) {
		RandomVariable* var = _dag->get_random_variable(target[i]);
/*		if(!check_target_type(i,var)) {
			string errMsg = "MCMC_move: target ";
			errMsg += var->name();
			errMsg += " has type ";
			errMsg += var->type();
			errMsg += " incompatible with ";
			errMsg += type;
			error(errMsg.c_str());
		}*/
		_target.push_back(var);
	}
	_mcmc->add_move(this,weight);
}
string MCMC_move::type() const {
	return _type;
}

vector<string> MCMC_move::targets() const {
	vector<string> ret(_target.size());
	int i;
	for(i=0;i<ret.size();i++) ret[i] = _target[i]->name();
	return ret;
}

MCMC_log::MCMC_log(DAG* dag, string filename, const int burnin, const int thinning, bool record_iter, bool record_move, bool record_proposal, string sep) : _dag(dag), _filename(filename), _burnin(burnin), _thinning(myutils::MAX(1,thinning)), _record_iter(record_iter), _record_move(record_move), _record_proposal(record_proposal), _sep(sep), _n_params(0), _n_params_loglik(0) {
	__fout = new ofstream;
	__fout->open(_filename.c_str());
	_fout = (ostream*)__fout;
	_mcmc = (MCMC*)_dag->get_inference_technique(); 
	_mcmc->add_log(this);
	if(_record_proposal) _dag->set_attempt_all_likelihoods(true);
}

MCMC_log::MCMC_log(DAG* dag, ostream* fout, const int burnin, const int thinning, bool record_iter, bool record_move, bool record_proposal, string sep) : _dag(dag), _filename(""), _fout(fout), __fout(0), _burnin(burnin), _thinning(myutils::MAX(1,thinning)), _record_iter(record_iter), _record_move(record_move), _record_proposal(record_proposal), _sep(sep), _n_params(0), _n_params_loglik(0) {
	((MCMC*)_dag->get_inference_technique())->add_log(this);
}

MCMC_log::~MCMC_log() {
	if(__fout!=0) {
		__fout->close();
		delete __fout;
	}
}

void MCMC_log::add_parameter(string var) {
	Variable* v = _dag->get_variable(var);
	add_parameter(v);
}

void MCMC_log::add_parameter(Variable* var) {
	if(var==0) error("MCMC_log::add_parameter(): void parameter pointer");
	_parameter.push_back(var);
	++_n_params;
}

void MCMC_log::add_loglik(string var) {
	Variable* v = _dag->get_variable(var);
	add_loglik(v);
}

void MCMC_log::add_loglik(Variable* var) {
	if(var==0) error("MCMC_log::add_loglik(): void parameter pointer");
	RandomVariable* rv = dynamic_cast<RandomVariable*>(var);
	if(!rv) {
		string errMsg = "MCMC_log::add_loglik(): ";
		errMsg += var->name() + " is not a parameter";
		error(errMsg.c_str());
	}
	_parameter_loglik.push_back(rv);
	++_n_params_loglik;
}

void MCMC_log::log_header() {
	if(_record_iter) {
		(*_fout) << "iteration" << _sep << "loglikelihood";
	}
	if(_record_move) {
		(*_fout) << _sep << "move" << _sep << "target";
	}
	int i;
	for(i=0;i<_n_params_loglik;i++) {
		(*_fout) << _sep;
		string str = "loglik(";
		str += _parameter_loglik[i]->name() + ")";
		(*_fout) << str;
	}
	for(i=0;i<_n_params;i++) {
		(*_fout) << _sep;
		_parameter[i]->print_header(*_fout,_sep);
	}
	(*_fout) << endl;
}

void MCMC_log::log(const int iter) {
	if((iter+1)>_burnin && (iter+1)%_thinning==0) {
		if(_record_iter) {
			(*_fout) << iter+1 << _sep << _mcmc->likelihood().LOG();
		}
		int i;
		if(_record_move) {
			(*_fout) << _sep << _mcmc->last_move() << _sep;
			vector<string> targets = _mcmc->last_targets();
			for(i=0;i<targets.size();i++) {
				if(i>0) (*_fout) << ";";
				(*_fout) << targets[i];
			}
		}
		for(i=0;i<_n_params_loglik;i++) {
			(*_fout) << _sep;
			(*_fout) << _parameter_loglik[i]->stored_likelihood().LOG();
		}
		for(i=0;i<_n_params;i++) {
			(*_fout) << _sep;
			_parameter[i]->print(*_fout,_sep);
		}
		(*_fout) << endl;
	}
}

bool MCMC_log::record_proposal() const {
	return _record_proposal;
}

MCMC::MCMC(DAG* dag, const int seed, const int niter, const double coutput_interval, const bool random_sweep, const int performance_interval) : _dag(dag), _niter(niter), _coutput_interval(coutput_interval), _random_sweep(random_sweep), _performance_interval(performance_interval), _n_moves(0), _last_move(-1) {
	_ran.setseed(seed);
	_coutput = (_coutput_interval>0) ? true : false;
	_monitor_performance = (_performance_interval>0) ? true : false;
	dag->set_inference_technique(this);
}

MCMC::~MCMC() {
	int i;
	for(i=0;i<_move.size();i++) {
		delete _move[i];
	}
	for(i=0;i<_log.size();i++) {
		delete _log[i];
	}
}

void MCMC::add_move(MCMC_move* move, const double weight) {
	_move.push_back(move);
	_weight.push_back(weight);
	++_n_moves;
}

void MCMC::add_log(MCMC_log* log) {
	_log.push_back(log);
}

void MCMC::perform_inference() {
	normalize_weights();
	_likelihood = _dag->likelihood();
	_dag->ready();
	if(_likelihood.iszero()) error("MCMC::perform_inference(): initial likelihood is zero");
	if(_likelihood!=_likelihood) error("MCMC::perform_inference(): initial likelihood is bad");
	clock_t start_t = clock(), current_t;
	clock_t next_t = start_t+(clock_t)((double)CLOCKS_PER_SEC*_coutput_interval);
	vector< MCMC_log* >::iterator logit;
	// Log headings (if necessary)
	for(logit=_log.begin();logit!=_log.end();logit++) {
		(*logit)->log_header();
	}
	// Log initial state (if necessary)
	for(logit=_log.begin();logit!=_log.end();logit++) {
		(*logit)->log(0);
	}
	// Performance monitor (if necessary)
	if(_monitor_performance) {
		_nacc = Matrix<int>((int)ceil((double)_niter/(double)_performance_interval),_n_moves,0);
		_npro = Matrix<int>((int)ceil((double)_niter/(double)_performance_interval),_n_moves,0);
	}
	for(iter=1;iter<_niter;iter++) {
		if(_random_sweep) {
			propose();
		}
		else {
			propose_systematic();
		}
		// Log (if necessary)
		for(logit=_log.begin();logit!=_log.end();logit++) {
			(*logit)->log(iter);
		}
		// Monitor performance (if necessary)
		if(_monitor_performance) {
			record_performance();
		}
		// Update screen (if requested)
		if(_coutput && ((current_t=clock())>next_t)) {
			cout << "\rDone " << (iter+1) << " of " << _niter << " iterations in " << (double)(current_t-start_t)/(double)CLOCKS_PER_SEC << " s " << flush;
			next_t = current_t+(clock_t)((double)CLOCKS_PER_SEC*_coutput_interval);
		}
		
		// Check likelihood
/*		if(iter%10000==0) {
			_dag->reset_all();
			mydouble lik2 = _dag->likelihood();
			if(fabs(lik2.LOG()-_likelihood.LOG())>1e-2) {
				cout << "\rlik1 = " << _likelihood.LOG() << " lik2 = " << lik2.LOG() << endl;
			}
		}*/
	}
	if(_coutput) cout << "\rDone " << _niter << " of " << _niter << " iterations in " << (double)(clock()-start_t)/(double)CLOCKS_PER_SEC << " s \n" << flush;
	
	if(_monitor_performance) {
		cout << endl << "Performance monitor" << endl << endl;
		const char tab = '\t';
		int i,j;
		for(i=0;i<_n_moves;i++) {
			cout << _move[i]->type() << ":";
			for(j=0;j<_move[i]->targets().size();j++) {
				cout << " " << _move[i]->targets()[j];
			}
			cout << endl;
			cout << "To iteration" << tab << "# proposed" << tab << "# accepted" << tab << "Proportion" << endl;
			for(j=0;j<_npro.nrows();j++) {
				cout << _performance_interval*(j+1) << tab << _npro[j][i] << tab << _nacc[j][i] << tab << ((double)_nacc[j][i])/((double)_npro[j][i]) << endl;
			}
			cout << endl;
		}
		cout << endl;
	}
}

Random* MCMC::get_ran() {
	return &_ran;
}

void MCMC::propose() {
	int move;
/*	static int mv;
	if(iter==5500) {
		for(move=0;move<_n_moves-1;move++) {
			if(_move[move]->targets()==vector<string>(1,"kappa1")) break;
		}
		if(move==_n_moves-1) error("Arse");
		mv = move;
	}
	if(iter>=5500) {
		return propose(mv);
	}*/
	double U = _ran.U();
	for(move=0;move<_n_moves-1;move++) {
		if(U<_cum_prob[move]) break;
	}
	_last_move = move;
	_move[move]->go();
	//propose(move);
}

void MCMC::normalize_weights() {
	if(_move.size()==0) error("MCMC::normalize_weights(): no moves added");
	_cum_prob = vector<double>(_move.size());
	double tot = 0.0;
	int i;
	for(i=0;i<_n_moves;i++) {
		tot += _weight[i];
	}
	double run_tot = 0.0;
	for(i=0;i<_n_moves;i++) {
		run_tot += _weight[i];
		_cum_prob[i] = run_tot/tot;
	}
	_sys_inc = 1.0/tot;
}

mydouble MCMC::likelihood() const {
	return _likelihood;
}

mydouble MCMC::alpha() const {
	return _alpha;
}

bool MCMC::accept() const {
	return _accept;
}

string MCMC::last_move() const {
	return (_last_move==-1) ? "Initialize" : _move[_last_move]->type();
}

vector<string> MCMC::last_targets() const {
	return (_last_move==-1) ? vector<string>(1,"none") : _move[_last_move]->targets();
}

void MCMC::propose_systematic() {
	int move;
	const double mul = _sys_inc/2.0 + (double)iter*_sys_inc;
	double U = mul-floor(mul);
	for(move=0;move<_n_moves-1;move++) {
		if(U<=_cum_prob[move]) break;
	}
	_last_move = move;
	_move[move]->go();
	//propose(move);
}

DAG* MCMC::dag() {
	return _dag;
}

mydouble MCMC::update_likelihood() {
	_old_likelihood = _likelihood;
	_likelihood = _dag->likelihood();
	return _likelihood;
}

mydouble MCMC::revert_likelihood() {
	_likelihood = _old_likelihood;
	return _likelihood;
}

void MCMC::record_proposal() {
	vector< MCMC_log* >::iterator logit;
	for(logit=_log.begin();logit!=_log.end();logit++) {
		if((*logit)->record_proposal()) (*logit)->log(iter);
	}
}

void MCMC::set_alpha(const mydouble& a) {
	_alpha = a;
}

void MCMC::set_accept(const bool a) {
	_accept = a;
}

Random* MCMC::ran() {
	return &_ran;
}

void MCMC::record_performance() {
	const int itv = iter/_performance_interval;
	_npro[itv][_last_move]++;
	if(_accept) _nacc[itv][_last_move]++;
}
	
} // namespace gcat
