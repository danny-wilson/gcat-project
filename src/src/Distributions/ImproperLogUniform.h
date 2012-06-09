/*  Copyright 2012 Daniel Wilson.
 *
 *  ImproperLogUniform.h
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
#ifndef _IMPROPER_LOG_UNIFORM_DISTRIBUTION_H_
#define _IMPROPER_LOG_UNIFORM_DISTRIBUTION_H_
#include <DAG/Distribution.h>
#include <RandomVariables/Continuous.h>

namespace gcat {

class ImproperLogUniformDistribution : public Distribution {
public:
	// Constructor
	ImproperLogUniformDistribution(string name="", DAG* dag=0);
	// Copy constructor
	ImproperLogUniformDistribution(const ImproperLogUniformDistribution &x);
	// Implementation of virtual function inherited from base class Distribution
	bool check_random_variable_type(RandomVariable* random_variable);
	// Implementation of virtual function inherited from base class
	bool check_parameter_type(const int i, Variable* parameter);
	
	// Compute log-likelihood
	mydouble likelihood(const RandomVariable* rv, const Value* val);
};
	
} // namespace gcat


#endif //_IMPROPER_LOG_UNIFORM_DISTRIBUTION_H_



