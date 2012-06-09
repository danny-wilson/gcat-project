/*  Copyright 2012 Daniel Wilson.
 *
 *  Transformation.cpp
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
#include <DAG/Transformation.h>
#include <DAG/DAG.h>

namespace gcat {

const string TransformationParameterName[0] = {};

Transformation::Transformation(const string* parameter_name, const int n_params) : DependentVariable(parameter_name,n_params) {
	if(getDAG()!=0) getDAG()->add_transformation(this);
}

Transformation::Transformation(const Transformation &var) : DependentVariable((const DependentVariable&)var) {
}

Transformation::~Transformation() {};

string Transformation::validate() const {
	// Warn if no daughters or parents
	if(is_orphan() && n_child_distributions()==0 && n_child_transformations()==0) {
		string wrnMsg = "Transformation ";
		wrnMsg += name();
		wrnMsg += " of type ";
		wrnMsg += type();
		wrnMsg += " is stranded";
		myutils::warning(wrnMsg.c_str());
	}
	return Parameter::validate();
}

// Signalling function: can be over-written in derived classes
void Transformation::receive_signal_from_parent(const Value* v, const Variable::Signal sgl) {
	send_signal_to_children(sgl);
}
	
} // namespace gcat

