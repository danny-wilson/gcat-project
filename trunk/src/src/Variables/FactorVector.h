/*  Copyright 2012 Daniel Wilson.
 *
 *  FactorVector.h
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
#ifndef _FACTOR_VECTOR_VARIABLE_H_
#define _FACTOR_VECTOR_VARIABLE_H_
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

// Abstract base class, guarantees methods called get_int(const int i), etc and implements print() methods
class FactorVectorVariable : public Value, public LengthProperty {
public:
	// Constructor
	FactorVectorVariable() {};
	// Copy constructor
	FactorVectorVariable(const FactorVectorVariable &x) {};
	// Destructor
	virtual ~FactorVectorVariable() {};
	// Get length of the variable. Inherited from LengthProperty
	//virtual int length() const = 0;
	// Get value at position i
	virtual int get_int(const int i) const = 0;
	// Get string at position i: default implementation
	virtual string get_string(const int i) const {
		if(i<0 || i>=length()) error("FactorVectorVariable::get_string(): index out of range");
		return to_string(get_int(i));
	}
	// Number of levels
	virtual int nlevels() const = 0;
	// Levels
	virtual vector< string > levels() const = 0;
	// Get vector of values
	virtual vector<int> get_ints() const = 0;
	// Convert string to integer
	virtual int to_int(const string s) const = 0;
	// Convert integer to string
	virtual string to_string(const int i) const = 0;
	// Get vector of strings: default implementation
	virtual vector<string> get_strings() const {
		vector< string > s(length());
		int i;
		for(i=0;i<length();i++) {
			s[i] = get_string(get_int(i));
		}
		return s;
	}
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
				out << get_string(i);
			}
			catch (BadValueException &e) {
				out << "NA";
			}
		}
	}
};
	
} // namespace gcat

#endif // _FACTOR_VECTOR_VARIABLE_H_
