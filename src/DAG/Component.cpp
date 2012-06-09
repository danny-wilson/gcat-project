/*  Copyright 2012 Daniel Wilson.
 *
 *  Component.cpp
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
#include <DAG/DAG.h>
#include <DAG/Component.h>

namespace gcat {

DAGcomponent::DAGcomponent(string name, DAG* dag, string type) : _name(name), _DAG(dag), _type(type) {
}

DAGcomponent::DAGcomponent(const DAGcomponent& x) : _DAG(x._DAG), _name(x._name), _type(x._type) {
}

DAGcomponent::~DAGcomponent() {
}

string DAGcomponent::type() const {
	return _type;
}

string DAGcomponent::name() const {
	return _name;
}

void DAGcomponent::setDAG(DAG *dag) {
	if(_DAG!=0 && _DAG!=dag) error("DAGcomponent::setDAG(): DAG already set");
	_DAG = dag;
}

DAG* DAGcomponent::getDAG() const {
	return _DAG;
}

bool DAGcomponent::isvalid() const {
	return (validate()=="");
}

string DAGcomponent::validate() const {
	return "";
}

void DAGcomponent::assert_validity() const {
	string msg = validate();
	if(msg!="") {
		msg = "DAGcomponent::assert_validity(): " + msg;
		error(msg.c_str());
	}
}

} // namespace gcat
