/*  Copyright 2012 Daniel Wilson.
 *
 *  ContinuousVector.cpp
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
#include <RandomVariables/ContinuousVector.h>

namespace gcat {

ContinuousVectorRV::ContinuousVectorRV(const int n, string name, DAG* dag, const vector<double> values) : DAGcomponent(name,dag), RandomVariable(), _n(n),
_value(values), _has_changed(vector<bool>(_n,true)) {
}

ContinuousVectorRV::ContinuousVectorRV(const ContinuousVectorRV& x) : DAGcomponent(x), RandomVariable(x), _n(x._n), _value(x._value),
_previous_value(x._previous_value), _has_changed(x._has_changed) {
}

ContinuousVectorRV::~ContinuousVectorRV() {};

void ContinuousVectorRV::set(const int i, const double value) {
	_value[i] = value;
	_has_changed[i] = true;
	act_on_signal(_SET);
	send_signal_to_children(_SET);
}

void ContinuousVectorRV::set(const vector<double>& value) {
	_value = value;
	_has_changed = vector<bool>(_n,true);
	act_on_signal(_SET);
	send_signal_to_children(_SET);
}

void ContinuousVectorRV::set(const vector<int>& pos, const vector<double>& value) {
	int i;
	for(i=0;i<pos.size();i++) {
		_value[pos[i]] = value[i];
		_has_changed[pos[i]] = true;
	}
	act_on_signal(_SET);
	send_signal_to_children(_SET);
}

void ContinuousVectorRV::propose(const int i, const double value) {
	_previous_value[i] = value;
	_value[i] = value;
	_has_changed[i] = true;
	act_on_signal(_PROPOSE);
	send_signal_to_children(_PROPOSE);
}

void ContinuousVectorRV::propose(const vector<double>& value) {
	_previous_value = value;
	_value = value;
	_has_changed = vector<bool>(_n,true);
	act_on_signal(_PROPOSE);
	send_signal_to_children(_PROPOSE);
}

void ContinuousVectorRV::propose(const vector<int>& pos, const vector<double>& value) {
	_previous_value = value;
	int i;
	for(i=0;i<pos.size();i++) {
		_value[pos[i]] = value[i];
		_has_changed[pos[i]] = true;
	}
	act_on_signal(_PROPOSE);
	send_signal_to_children(_PROPOSE);
}

void ContinuousVectorRV::accept() {
	_has_changed = vector<bool>(_n,false);
	act_on_signal(_ACCEPT);
	send_signal_to_children(_ACCEPT);
}

void ContinuousVectorRV::revert() {
	_value = _previous_value;
	_has_changed = vector<bool>(_n,false);
	act_on_signal(_REVERT);
	send_signal_to_children(_REVERT);
}

int ContinuousVectorRV::length() const {
	return _n;
}

double ContinuousVectorRV::get_double(const int i) const {
	return _value[i];
}

vector<double> ContinuousVectorRV::get_doubles() const {
	return _value;
}

bool ContinuousVectorRV::has_changed(const int i) const {
	return _has_changed[i];
}

vector<bool> ContinuousVectorRV::has_changed() const {
	return _has_changed;
}
	
} // namespace gcat
