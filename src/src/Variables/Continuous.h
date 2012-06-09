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
#ifndef _CONTINOUS_VARIABLE_H_
#define _CONTINOUS_VARIABLE_H_
#include <DAG/Value.h>
#include <string>
#include <ostream>

using std::string;
using std::ostream;

namespace gcat {

// Abstract base class, guarantees a method called get_double() and implements print() methods
class ContinuousVariable : public Value {
public:
	// Constructor
	ContinuousVariable() {};
	// Copy constructor
	ContinuousVariable(const ContinuousVariable &x) {};
	// Destructor
	virtual ~ContinuousVariable() {};
	// Get value
	virtual double get_double() const = 0;
	// Print header (implementation of inherited method)
	virtual void print_header(ostream& out, string sep) {
		out << name();
	}
	// Print value (implementation of inherited method)	
	virtual void print(ostream& out, string sep) {
		try {
			out << get_double();
		}
		catch (BadValueException &e) {
			out << "NA";
		}
	}
};
	
} // namespace gcat

#endif // _CONTINOUS_VARIABLE_H_
