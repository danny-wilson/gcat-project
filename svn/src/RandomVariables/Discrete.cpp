/*  Copyright 2012 Daniel Wilson.
 *
 *  Discrete.cpp
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
#include <RandomVariables/Discrete.h>

namespace gcat {

DiscreteRV::DiscreteRV(string name, DAG* dag, const int x) : DAGcomponent(name,dag,"DiscreteRV"), RandomVariable(), _value(x), _previous_value(0) {
}

DiscreteRV::DiscreteRV(const DiscreteRV &x) : DAGcomponent((const DAGcomponent&)x), RandomVariable((const RandomVariable&)x), _value(x._value), _previous_value(x._previous_value) {
}

DiscreteRV::~DiscreteRV() {};

void DiscreteRV::set(const int value) {
	_value = value;
	send_signal_to_children(_SET);
}

void DiscreteRV::propose(const int value) {
	_previous_value = _value;
	_value = value;
	send_signal_to_children(_PROPOSE);
}

void DiscreteRV::accept() {
	send_signal_to_children(_ACCEPT);
}

void DiscreteRV::revert() {
	_value = _previous_value;
	send_signal_to_children(_REVERT);
}

int DiscreteRV::get_int() const {
	return _value;
}
	
} // namespace gcat
