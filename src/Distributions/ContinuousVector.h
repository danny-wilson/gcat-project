/*  Copyright 2017 Daniel Wilson.
 *
 *  ContinuousVector.h
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
// This code based on ContinuousMosaic.h
#ifndef _CONTINUOUS_VECTOR_DISTRIBUTION_H_
#define _CONTINUOUS_VECTOR_DISTRIBUTION_H_
#include <DAG/CompoundDistribution.h>
#include <Variables/Continuous.h>

namespace gcat {

// Forward declaration
class ContinuousVectorRV;

class ContinuousVectorDistribution : public ContinuousVariable, public CompoundDistribution {
protected:
	// Internal used with the get_double() method
	double _x;
public:
	// Constructor
	ContinuousVectorDistribution(string name="", DAG* dag=0);
	// Copy constructor
	ContinuousVectorDistribution(const ContinuousVectorDistribution& x);
	
	// Implementation of virtual function inherited from base class Distribution
	bool check_random_variable_type(RandomVariable* random_variable);
	// Implementation of virtual function inherited from base class DependentVariable
	bool check_parameter_type(const int i, Variable* parameter);
	Distribution* get_marginal_distribution();
	
	// Compute likelihood
	mydouble likelihood(const RandomVariable* rv, const Value* val);
	// Necessary for likelihood: implementation of inherited virtual function
	double get_double() const;
	
};
	
} // namespace gcat

#endif // _CONTINUOUS_VECTOR_DISTRIBUTION_H_
