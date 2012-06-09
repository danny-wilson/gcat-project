/*  Copyright 2012 Daniel Wilson.
 *
 *  Transformation.h
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
#ifndef _TRANSFORMATION_H_
#define _TRANSFORMATION_H_
#include <set>
#include <DAG/Parameter.h>
#include <DAG/DependentVariable.h>
#include <vector>
#include <map>

using std::vector;
using std::map;
using std::multimap;
using std::iterator;
using std::pair;

namespace gcat {

/*	class Transformation: 
		Can have named parameter variable(s)
		Is intended for indirect manipulation of co-inherited types in derived classes by implementing update()
 */
class Transformation : public Parameter, public DependentVariable {
private:
	Value* _thisValue;
	
public:
	// Constructor
	Transformation(const string* parameter_name=0, const int n_params=0);
	// Copy constructor
	Transformation(const Transformation& var);
	// Destructor
	virtual ~Transformation();
		
	// Default behaviour for a Transformation is to call Variable::send_signal_to_children(sgl)
	virtual void receive_signal_from_parent(const Value* v, const Variable::Signal sgl);

protected:
	// Validate
	virtual string validate() const;
};
	
} // namespace gcat


#endif // _TRANSFORMATION_H_
