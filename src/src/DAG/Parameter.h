/*  Copyright 2012 Daniel Wilson.
 *
 *  Parameter.h
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
#ifndef _PARAMETER_H_
#define _PARAMETER_H_
#include <DAG/Variable.h>

namespace gcat {

// Base class for Random Variable and Transformation
class Parameter : public virtual Variable {
public:
	// Constructor
	Parameter() {};
	// Copy constructor
	Parameter(const Parameter& x) {};
	// Destructor
	virtual ~Parameter() {};
};
	
} // namespace gcat

#endif // _PARAMETER_H_
