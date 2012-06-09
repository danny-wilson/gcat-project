/*  Copyright 2012 Daniel Wilson.
 *
 *  Component.h
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
#ifndef _DAGCOMPONENT_H_
#define _DAGCOMPONENT_H_
#include <myerror.h>
#include <string>
#include <math.h>
#include <mydouble.h>

using myutils::error;
using std::string;

namespace gcat {

class DAG;

class DAGcomponent {
protected:
	DAG* _DAG;
	string _name;
	string _type;
public:
	// Constructor
	DAGcomponent(string name="", DAG* dag=0, string type="DAGcomponent");
	// Copy constructor
	DAGcomponent(const DAGcomponent& x);
	// Virtual Destructor
	virtual ~DAGcomponent();
	// Get type
	string type() const;
	// Get name
	string name() const;
	// Set DAG
	void setDAG(DAG* dag);
	// Get DAG
	DAG* getDAG() const;
	// Is it valid?
	bool isvalid() const;
	// Assert its validity (if invalid, error)
	void assert_validity() const;
protected:
	virtual string validate() const;
};
	
} // namespace gcat

#endif //_DAGCOMPONENT_H_
