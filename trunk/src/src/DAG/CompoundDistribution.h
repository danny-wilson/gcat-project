/*  Copyright 2012 Daniel Wilson.
 *
 *  CompoundDistribution.h
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
#ifndef _COMPOUND_DISTRIBUTION_H_
#define _COMPOUND_DISTRIBUTION_H_
#include <DAG/DAG.h>
#include <DAG/Distribution.h>
#include <DAG/RandomVariable.h>

namespace gcat {

class CompoundDistribution : public Distribution, public RandomVariable {
public:
	// Constructor: call Distribution() and RandomVariable(), but instruct them not to add themselves to the DAG
	CompoundDistribution(const string* distribution_names, const int n_distributions, const string* parameter_names=0, const int n_parameters=0) :
		Distribution(parameter_names,n_parameters,false), RandomVariable(distribution_names,n_distributions,false) {
			if(getDAG()!=0) getDAG()->add_distribution(dynamic_cast<Distribution*>(this));
	}
	// Copy constructor
	CompoundDistribution(const CompoundDistribution& x) :
		Distribution((const Distribution&)x), RandomVariable((const RandomVariable&)x) {
	}
	// Destructor
	virtual ~CompoundDistribution() {};

	// Redefine this function inherited from RandomVariable. Propagate the signal to child RVs
	virtual void receive_signal_from_parent(const Distribution* dist, const Signal sgl) {
		propagate_signal_to_children(sgl);
	}

protected:
	virtual string validate() const {
		string validRV = RandomVariable::validate();
		if(validRV!="") return validRV;
		return Distribution::validate();
	}
};
	
} // namespace gcat

#endif // _COMPOUND_DISTRIBUTION_H_
