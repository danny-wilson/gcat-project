/*  Copyright 2012 Daniel Wilson.
 *
 *  Value.h
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
#ifndef _VALUE_H_
#define _VALUE_H_
#include <DAG/Variable.h>
#include <exception>
#include <string>

namespace gcat {

// Base class for all objects promising to return a value, e.g. ContinuousVariable
class Value : public virtual Variable {
public:
	// Constructor
	Value() {};
	// Copy constructor
	Value(const Value & x) {};
	// Destructor
	virtual ~Value() {};
};

// Exception class for handling bad values
class BadValueException : public std::exception {
private:
	const Value *_v;
	std::string _msg;
public:
	// Constructor
	BadValueException(const Value *v, string msg="") : _v(v), _msg(msg) {};
	// Override inherited what method
	virtual const char* what() const throw() {
		std::string errMsg = "Bad value exception in object " + _v->name() + " of type " + _v->type();
		if(_msg!="") errMsg += ":\n" + _msg;
		return errMsg.c_str();
	}
	// Destructor
	~BadValueException() throw() {};
};
	
} // namespace gcat

#endif // _VALUE_H_
