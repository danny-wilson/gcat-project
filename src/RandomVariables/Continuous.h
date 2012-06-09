/*  Copyright 2012 Daniel Wilson.
 *
 *  Continuous.h
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
#ifndef _CONTINOUS_RANDOM_VARIABLE_H_
#define _CONTINOUS_RANDOM_VARIABLE_H_
#include <Variables/Continuous.h>
#include <DAG/RandomVariable.h>

namespace gcat {

class ContinuousRV : public ContinuousVariable, public RandomVariable {
private:
	double _value, _previous_value;
public:
	// Constructor
	ContinuousRV(string name="", DAG* dag=0, const double x=0.0);
	// Copy constructor
	ContinuousRV(const ContinuousRV &x);
	// Destructor
	virtual ~ContinuousRV();
	
	// Set value
	void set(const double value);
	// Propose value
	void propose(const double value);
	// Accept value
	void accept();
	// Revert to value
	void revert();

	// Implementation of inherited methods
	double get_double() const;
};
	
} // namespace gcat

#endif // _CONTINOUS_RANDOM_VARIABLE_H_

