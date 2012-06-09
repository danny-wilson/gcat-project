/*  Copyright 2012 Daniel Wilson.
 *
 *  LogUniform.h
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
#ifndef _LOG_UNIFORM_DISTRIBUTION_H_
#define _LOG_UNIFORM_DISTRIBUTION_H_
#include <DAG/Distribution.h>
#include <RandomVariables/Continuous.h>

namespace gcat {

class LogUniformDistribution : public Distribution {
public:
	// Constructor
	LogUniformDistribution(string name="", DAG* dag=0);
	// Copy constructor
	LogUniformDistribution(const LogUniformDistribution& x);
	// Implementation of virtual function inherited from base class Distribution
	bool check_random_variable_type(RandomVariable* random_variable);
	// Implementation of virtual function inherited from class DependentVariable
	bool check_parameter_type(const int i, Variable* parameter);
	// Convenience functions
	void set_min(ContinuousVariable* min);
	void set_max(ContinuousVariable* max);
	ContinuousVariable const* get_min() const;
	ContinuousVariable const* get_max() const;
	
	// Compute log-likelihood
	mydouble likelihood(const RandomVariable* rv, const Value* val);
};
	
} // namespace gcat

#endif // _LOG_UNIFORM_DISTRIBUTION_H_