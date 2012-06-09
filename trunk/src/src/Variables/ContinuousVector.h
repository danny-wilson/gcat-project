/*  Copyright 2012 Daniel Wilson.
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
#ifndef _CONTINOUS_VECTOR_VARIABLE_H_
#define _CONTINOUS_VECTOR_VARIABLE_H_
#include <DAG/Value.h>
#include <string>
#include <ostream>
#include <vector.h>
#include <vector>
#include <Properties/Length.h>

using std::string;
using std::ostream;
using myutils::Vector;
using std::vector;

namespace gcat {

// Abstract base class, guarantees methods called get_double(const int i), etc and implements print() methods
class ContinuousVectorVariable : public Value, public LengthProperty {
public:
	// Constructor
	ContinuousVectorVariable() {};
	// Copy constructor
	ContinuousVectorVariable(const ContinuousVectorVariable &x) {};
	// Destructor
	virtual ~ContinuousVectorVariable() {};
	// Get value at position i
	virtual double get_double(const int i) const = 0;
	// Get vector of values
	virtual vector<double> get_doubles() const = 0;
	// Has the value changed at position i?
	virtual bool has_changed(const int i) const = 0;
	// Has the value changed at each position?
	virtual vector<bool> has_changed() const = 0;
	// Print header (implementation of inherited method)
	virtual void print_header(ostream& out, string sep) {
		int i;
		for(i=0;i<length();i++) {
			if(i>0) out << sep;
			out << name() << i;
		}
	}
	// Print value (implementation of inherited method)	
	virtual void print(ostream& out, string sep) {
		int i;
		for(i=0;i<length();i++) {
			if(i>0) out << sep;
			try {
				out << get_double(i);
			}
			catch (BadValueException &e) {
				out << "NA";
			}
		}
	}
};
	
} // namespace gcat

#endif // _CONTINOUS_VECTOR_VARIABLE_H_


