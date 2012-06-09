/*  Copyright 2012 Daniel Wilson.
 *
 *  Concatenate.cpp
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
#include <Transformations/Concatenate.h>
#include <string>
#include <sstream>

using std::string;
using std::stringstream;

namespace gcat {

const string* ConcatenateTransformParameterNames(const int n) {
	string* ret = new string[n];
	int i;
	for(i=0;i<n;i++) {
		stringstream s;
		s << "item" << i;
		ret[i] = s.str();
	}
	return ret;
}

ConcatenateTransform::ConcatenateTransform(const int n, const int L, string name, DAG* dag) : DAGcomponent(name,dag,"ConcatenateTransform"), Transformation(ConcatenateTransformParameterNames(n),n), _n(n), _x(0), _x_prev(0), _cum_L(n), _L(L), _is_scalar(n), _has_changed(0), _recalculate(true), _init(false) {
}

ConcatenateTransform::ConcatenateTransform(const ConcatenateTransform& x) : DAGcomponent(x), Transformation(x), _n(x._n), _x(x._x), _x_prev(x._x_prev), _cum_L(x._cum_L), _L(x._L), _is_scalar(x._is_scalar), _has_changed(x._has_changed), _recalculate(x._recalculate), _init(x._init) {
}

int ConcatenateTransform::length() const {
//	if(!_init) error("ConcatenateTransform::length(): not yet initialized, property unavailable");
	return _L;
}

double ConcatenateTransform::get_double(const int i) const {
	if(_recalculate) recalculate();
	return _x[i];
}

vector<double> ConcatenateTransform::get_doubles() const {
	if(_recalculate) recalculate();
	return _x;
}

bool ConcatenateTransform::has_changed(const int i) const {
	if(_recalculate) recalculate();
	return _has_changed[i];
}

vector<bool> ConcatenateTransform::has_changed() const {
	if(_recalculate) recalculate();
	return _has_changed;
}

bool ConcatenateTransform::check_parameter_type(const int i, Variable* parameter) {
	bool is_scalar = dynamic_cast<ContinuousVariable*>(parameter);
	bool is_vector = dynamic_cast<ContinuousVectorVariable*>(parameter);
	return(is_scalar || is_vector);
}

void ConcatenateTransform::receive_signal_from_parent(const Value* v, const Variable::Signal sgl) {
	if(sgl==Variable::_ACCEPT) {
		_has_changed = vector<bool>(_L,false);
	}
	else if (sgl==Variable::_REVERT) {
		_x = _x_prev;
		_has_changed = vector<bool>(_L,false);
	}
	else if(sgl==Variable::_SET) {
		_recalculate = true;
	}
	else if(sgl==Variable::_PROPOSE) {
		_recalculate = true;
	}
	// Call default implementation, which is to call Variable::send_signal_to_children(sgl)
	Transformation::receive_signal_from_parent(v,sgl);
}

void ConcatenateTransform::recalculate() const {
	int i, j;
	if(!_init) {
		initialize();
		for(i=0;i<_n;i++) {
			if(_is_scalar[i]) {
				_x[_cum_L[i]] = ((const ContinuousVariable*)get_parameter(i))->get_double();
			}
			else {
				const ContinuousVectorVariable* v = (const ContinuousVectorVariable*)get_parameter(i);
				for(j=0;j<v->length();j++) {
					_x[_cum_L[i]+j] = v->get_double(j);
				}
			}
		}
		_has_changed = vector<bool>(_L,true);
	}
	else {
		_x_prev = _x;
		for(i=0;i<_n;i++) {
			if(_is_scalar[i]) {
				const int ix = _cum_L[i];
				_x[ix] = ((const ContinuousVariable*)get_parameter(i))->get_double();
				_has_changed[ix] = _x[ix]==_x_prev[ix];
			}
			else {
				const ContinuousVectorVariable* v = (const ContinuousVectorVariable*)get_parameter(i);
				for(j=0;j<v->length();j++) {
					const int ix = _cum_L[i]+j;
					_x[ix] = v->get_double(j);
					_has_changed[ix] = _x[ix]==_x_prev[ix];
				}
			}
		}
	}
	_recalculate = false;
}

void ConcatenateTransform::initialize() const {
	int i;
	_L = 0;
	for(i=0;i<_n;i++) {
		_cum_L[i] = _L;
		const Value* v = get_parameter(i);
		const ContinuousVariable* cv = dynamic_cast<const ContinuousVariable*>(v);
		const ContinuousVectorVariable* cvv = dynamic_cast<const ContinuousVectorVariable*>(v);
		if(cv) {
			_is_scalar[i] = true;
			_L += 1;
		}
		else if(cvv) {
			_is_scalar[i] = false;
			_L += cvv->length();
		}
		else {
			error("ConcatenateTransform::initialize(): parameter of wrong type");
		}
	}
	_x = vector<double>(_L);
	_x_prev = vector<double>(_L);
	_has_changed = vector<bool>(_L,true);
	_init = true;
}
	
} // namespace gcat
