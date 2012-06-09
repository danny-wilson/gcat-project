/*  Copyright 2012 Daniel Wilson.
 *
 *  Discrete.h
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
#ifndef _DISCRETE_RANDOM_VARIABLE_H_
#define _DISCRETE_RANDOM_VARIABLE_H_
#include <Variables/Discrete.h>
#include <DAG/RandomVariable.h>

namespace gcat {

class DiscreteRV : public DiscreteVariable, public RandomVariable {
private:
	int _value, _previous_value;
public:
	// Constructor
	DiscreteRV(string name="", DAG* dag=0, const int x=0.0);
	// Copy constructor
	DiscreteRV(const DiscreteRV &x);
	// Destructor
	virtual ~DiscreteRV();
	
	// Set value
	virtual void set(const int value);
	// Propose value
	virtual void propose(const int value);
	// Accept value
	virtual void accept();
	// Revert to value
	virtual void revert();
	
	// Implementation of inherited methods
	virtual int get_int() const;
};
	
} // namespace gcat

#endif // _DISCRETE_RANDOM_VARIABLE_H_


