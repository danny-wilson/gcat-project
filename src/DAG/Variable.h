/*  Copyright 2012 Daniel Wilson.
 *
 *  Variable.h
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
#ifndef _VARIABLE_H_
#define _VARIABLE_H_
#include <set>
#include <DAG/Component.h>
#include <ostream>

using std::iterator;
using std::pair;
using std::multiset;
using std::ostream;

namespace gcat {

// Forward declarations
class Value;
class Distribution;
class Transformation;

/*	class Variable: 
		Can parameterize arbitrary distributions and transformations
		Can signal changes in state of derived class to child components using send_signal_to_children()
		Virtual print() and print_header() method
 */
class Variable : public virtual DAGcomponent {
public:
	enum Signal {_INITIALIZE, _SET, _PROPOSE, _ACCEPT, _REVERT};
protected:
	// Set of child distributions parameterized by this variable
	multiset< Distribution* > _child_distribution;
	// Set of child transformations parameterized by this variable
	multiset< Transformation* > _child_transformation;
	// Point to self of Value type
	mutable Value* _thisValue;
	
public:
	// Constructor
	Variable();
	// Copy constructor
	Variable(const Variable& var);
	// Destructor
	virtual ~Variable();

	// Add a child distribution which this variable will parameterize
	void add_child_distribution(Distribution* child);	
	// Remove a child distribution
	void remove_child_distribution(Distribution* child);
	// Report the number of child distributions
	int n_child_distributions() const;

	// Add a child transformation which this variable will parameterize
	void add_child_transformation(Transformation* child);	
	// Remove a child transformation
	void remove_child_transformation(Transformation* child);
	// Report the number of child transformations
	int n_child_transformations() const;
	
	// Print the header for the variable to a stream
	virtual void print_header(ostream& out, string sep="\t") = 0;
	// Print the variable to a stream
	virtual void print(ostream& out, string sep="\t") = 0;

	// Returns a dynamically-cast Value* pointer to this object (or a null pointer if the cast is invalid)
	const Value* to_Value() const;

protected:
	// Signal to _child Distributions and Transformations that the value has changed. Call from derived function e.g. ContinuousRV::set(T)
	void send_signal_to_children(const Signal sgl);
	// Validate
	virtual string validate() const;
};
	
} // namespace gcat

#endif //_VARIABLE_H_
