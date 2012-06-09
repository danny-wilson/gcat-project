/*  Copyright 2012 Daniel Wilson.
 *
 *  Matrix.h
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
// NB:- assumed Continuous
#ifndef _MATRIX_VARIABLE_H_
#define _MATRIX_VARIABLE_H_
#include <DAG/Value.h>
#include <myerror.h>
#include <string>
#include <ostream>

using std::string;
using std::ostream;

namespace gcat {

// Abstract base class
class MatrixVariable : public Value {
public:
	// Constructor
	MatrixVariable() {};
	// Copy constructor
	MatrixVariable(const MatrixVariable &x) {};
	// Destructor
	virtual ~MatrixVariable() {};
	// Number of rows
	virtual int nrows() const = 0;
	// Number of columns
	virtual int ncols() const = 0;
	// Get value
	virtual double get_double(const int i, const int j) const = 0;
	// 
	// Print header (no implementation but may be overwritten in derived class)
	virtual void print_header(ostream& out, string sep) {
		myutils::warning("MatrixVariable::print_header(): no print method available");
	}
	// Print value (no implementation but may be overwritten in derived class)
	virtual void print(ostream& out, string sep) {
	}
};
	
} // namespace gcat

#endif // _MATRIX_VARIABLE_H_

