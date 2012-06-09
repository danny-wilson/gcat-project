/*  Copyright 2012 Daniel Wilson.
 *
 *  RandomVariable.h
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
#ifndef _RANDOM_VARIABLE_H_
#define _RANDOM_VARIABLE_H_
#include <set>
#include <DAG/Parameter.h>
#include <vector>
#include <map>

using std::vector;
using std::map;
using std::multimap;
using std::iterator;
using std::pair;

namespace gcat {

// Forward declarations
class Distribution;
class Value;

extern const string RandomVariableDistributionName[];

/*	class RandomVariable: 
 Can have named parent distribution(s)
 Can signal changes in state of derived class to parent distributions using send_signal_to_parents()
 Is intended base for concrete derived classes that are jointly derived from type classes, and have mutator
 functions which call the signalling functions send_signal_to_parents() and the inherited send_signal_to_children().
 */
class RandomVariable : public Parameter {
private:
	// What was the last action?
	//enum {_INITIALIZE,_SET,_PROPOSE} _last_action;
	// Does the likelihood need calculating?
	bool _calculate_likelihood;
	// Storage of current likelihood and, if the current state is merely a proposal, previous likelihood
	mydouble _likelihood, _previous_likelihood;

	// Number of parent distributions
	int _np;
	// Vector of pointers to parent distributions, and an index of those distributions
	// (Possession of multiple distributions requires a valid factorization of the likelihood)
	vector< Distribution* > _parent;
	multimap< Distribution* , int > _parent_index;
	// Vector of parent distribution names, and an index of those distribution names
	vector< string > _parent_name;
	map< string, int > _parent_name_index;
	
	// Temporary hack
	string rvname;
	
public:
	// Constructor
	RandomVariable(const string* parent_name=RandomVariableDistributionName, const int n_parents=1, const bool add_to_DAG=true);
	// Copy constructor
	RandomVariable(const RandomVariable& var);
	// Destructor
	virtual ~RandomVariable();
	
	// Likelihood functions
	double log_likelihood();
	mydouble likelihood();
	mydouble calculate_likelihood();
	mydouble stored_likelihood() const;
	
	// Number of parent distributions
	int n_parents() const;
	// Returns the parent number of a parent distributions, or -1 if not found
	int parent_number(string parent_name) const;
	// Returns the parent name of a numbered parent distribution
	string parent_name(int parent_number) const;
	// Clear the named parent distribution
	void clear_parent(string parent_name);
	// Clear the numbered parent distribution
	void clear_parent(const int i);
	// Sets a named parent distribution using Distribution* and dynamic type checking
	void set_parent(string parent_name, Distribution* parent);
	// Sets a numbered parent distribution using Distribution* and dynamic type checking
	void set_parent(const int i, Distribution* parent);
	// Returns an immutable pointer to a named parent distribution
	Distribution const* get_parent(string parent_name) const;
	// Returns an immutable pointer to a numbered parent distribution
	Distribution const* get_parent(const int i) const;
	// Returns an pointer to a named parent distribution
	Distribution* get_parent(string parent_name);
	// Returns an pointer to a numbered parent distribution
	Distribution* get_parent(const int i);
	// Is the variable an orphan (i.e. has no parent distribution set)?
	bool is_orphan() const;
	
	// Act upon a signal that the parent's parameters have changed
	virtual void receive_signal_from_parent(const Distribution* dist, const Signal sgl);	
	
protected:
	// Inherited from Variable: Signal to _child Distributions and Transformations that the value has changed. Call from derived function e.g. ContinuousRV::set(T)
	// void send_signal_to_children(const Signal sgl);
	// The following are to be deleted OR ARE THEY, because signalling is strictly parent->child NOT ANY MORE!!!
	// Signal to all interested parties that the value has changed.  Call from derived function e.g. ContinuousRV::set(T)
	//void send_signal(const Signal sgl);
	// Signal to _parent Distributions that the value has changed. Might call from derived function if only wish to notify parents
	//void send_signal_to_parents(const Signal sgl);
	// Act on a signal
	friend class DAG;
	virtual void act_on_signal(const Signal sgl);
	// Validate
	virtual string validate() const;
};
	
} // namespace gcat


#endif // _RANDOM_VARIABLE_H_
