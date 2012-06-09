/*  Copyright 2012 Daniel Wilson.
 *
 *  Distribution.h
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
#ifndef _DISTRIBUTION_H_
#define _DISTRIBUTION_H_
#include <set>
#include <DAG/DependentVariable.h>

using std::set;

namespace gcat {

class Variable;
class RandomVariable;
class Value;

class Distribution : public DependentVariable {
private:
	// Storage of current likelihood and, if the current state is merely a proposal, previous likelihood
	mydouble _likelihood, _previous_likelihood;
	
	// Set of random variables
	set< RandomVariable* > _random_variable;
	
public:
	// Constructor
	Distribution(const string* parameter_name=0, const int n_parameters=0, const bool add_to_DAG=true);
	// Copy constructor
	Distribution(const Distribution &x);
	// Destructor
	virtual ~Distribution();
	
	// Likelihood function: pass two versions of pointer to the same object to enable static casting
	virtual mydouble likelihood(const RandomVariable* rv, const Value* val) = 0;
	
	// Add a random variable
	virtual void add_random_variable(RandomVariable* random_variable);
	// Remove a random variable
	virtual void remove_random_variable(RandomVariable* random_variable);
	// Report number of random variables
	int n_random_variables() const;
	// Check the type of a random variable
	virtual bool check_random_variable_type(RandomVariable* random_variable) = 0;
	
	// Default behaviour for a Distribution is to call propagate_signal_to_children()
	virtual void receive_signal_from_parent(const Value* v, const Variable::Signal sgl);

protected:
	// Validate
	virtual string validate() const;
	// Get set of random variables
	set< RandomVariable* >& random_variable();
	// Propagate received signals to child RandomVariables
	void propagate_signal_to_children(const Variable::Signal sgl);
};
	
} // namespace gcat

#endif // _DISTRIBUTION_H_
