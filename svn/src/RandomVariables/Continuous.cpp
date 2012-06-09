/*  Copyright 2012 Daniel Wilson.
 *
 *  Continuous.cpp
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
#include <RandomVariables/Continuous.h>

namespace gcat {

ContinuousRV::ContinuousRV(string name, DAG* dag, const double x) : DAGcomponent(name,dag,"ContinuousRV"), RandomVariable(), _value(x), _previous_value(0) {
}

ContinuousRV::ContinuousRV(const ContinuousRV &x) : DAGcomponent((const DAGcomponent&)x), RandomVariable((const RandomVariable&)x), _value(x._value), _previous_value(x._previous_value) {
}

ContinuousRV::~ContinuousRV() {};

void ContinuousRV::set(const double value) {
	_value = value;
	act_on_signal(_SET);
	send_signal_to_children(_SET);
}

void ContinuousRV::propose(const double value) {
	_previous_value = _value;
	_value = value;
	act_on_signal(_PROPOSE);
	send_signal_to_children(_PROPOSE);
}

void ContinuousRV::accept() {
	act_on_signal(_ACCEPT);
	send_signal_to_children(_ACCEPT);
}

void ContinuousRV::revert() {
	_value = _previous_value;
	act_on_signal(_REVERT);
	send_signal_to_children(_REVERT);
}

double ContinuousRV::get_double() const {
	return _value;
}
	
} // namespace gcat
