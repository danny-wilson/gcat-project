/*  Copyright 2012 Daniel Wilson.
 *
 *  ExponentialQuantileVector.cpp
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
#include <Transformations/ExponentialQuantileVector.h>

namespace gcat {

const string ExponentialQuantileVectorTransformParameterNames[2] = {"lambda","quantile"};

ExponentialQuantileVectorTransform::ExponentialQuantileVectorTransform(const int n, string name, DAG* dag) : DAGcomponent(name,dag,"ExponentialQuantileVectorTransform"), Transformation(ExponentialQuantileVectorTransformParameterNames,2), _n(n), _lambda_changed(true), _quantile_changed(true), _x(n), _x_prev(n), _has_changed(n,true), _bad(n), _bad_prev(n) {
}

ExponentialQuantileVectorTransform::ExponentialQuantileVectorTransform(const ExponentialQuantileVectorTransform& x) : DAGcomponent(x), Transformation(x), _n(x._n), _lambda_changed(x._lambda_changed), _quantile_changed(x._quantile_changed), _x(x._x), _x_prev(x._x_prev), _has_changed(x._has_changed), _bad(x._bad), _bad_prev(x._bad_prev)  {
}

int ExponentialQuantileVectorTransform::length() const {
	return _n;
}

double ExponentialQuantileVectorTransform::get_double(const int i) const {
	if(_recalculate) recalculate();
	// Only throw if the value is requested
	if(_bad[i]) throw BadValueException(to_Value(),"Standard deviation or quantile out of range");
	return _x[i];
}

void ExponentialQuantileVectorTransform::recalculate() const {
	//	if(_mean_changed || _sd_changed || _quantile_changed) {
	// Recalculate
	double lambda = get_lambda()->get_double();
	if(!lambda>0) _bad = vector<bool>(_n,true);
	else {
		int pos;
		for(pos=0;pos<_n;pos++) {
			double quantile = get_quantile()->get_double(pos);
			if(!(quantile>0 & quantile<1)) _bad[pos] = true;
			else {
				_x[pos] = -log(1.0-quantile)/lambda;
				_bad[pos] = false;
			}
		}
	}
	_lambda_changed = _quantile_changed = false;
	//	}
	_recalculate = false;
}

vector<double> ExponentialQuantileVectorTransform::get_doubles() const {
	vector<double> ret(_n);
	int i;
	for(i=0;i<_n;i++) ret[i] = get_double(i);
	return ret;
}

bool ExponentialQuantileVectorTransform::has_changed(const int i) const {
	return _has_changed[i];
}

vector<bool> ExponentialQuantileVectorTransform::has_changed() const {
	return _has_changed;
}

bool ExponentialQuantileVectorTransform::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		case 0:	// lambda
			return(dynamic_cast<ContinuousVariable*>(parameter));
		case 1:	// quantile
			return(dynamic_cast<ContinuousVectorVariable*>(parameter));
		default:
			error("ExponentialQuantileVectorTransform::check_parameter_type(): parameter not found");
	}
	return false;
}

void ExponentialQuantileVectorTransform::set_lambda(ContinuousVariable* mean) {
	set_parameter(0,(Variable*)mean);
}

void ExponentialQuantileVectorTransform::set_quantile(ContinuousVectorVariable* quantile) {
	set_parameter(1,(Variable*)quantile);
}

ContinuousVariable const* ExponentialQuantileVectorTransform::get_lambda() const {
	return (ContinuousVariable const*)get_parameter(0);
}

ContinuousVectorVariable const* ExponentialQuantileVectorTransform::get_quantile() const {
	return (ContinuousVectorVariable const*)get_parameter(1);
}

void ExponentialQuantileVectorTransform::receive_signal_from_parent(const Value* v, const Variable::Signal sgl) {
	if(sgl==Variable::_ACCEPT || sgl==Variable::_REVERT) {
		_lambda_changed = _quantile_changed = false;
		_has_changed = vector<bool>(_n,false);
	}
	if(sgl==Variable::_SET || sgl==Variable::_PROPOSE) {
		_recalculate = true;
	}
	if(v==(const Value*)get_lambda()) {
		if(sgl==Variable::_SET) {
			_lambda_changed = true;
			_has_changed = vector<bool>(_n,true);
		}
		else if(sgl==Variable::_PROPOSE) {
			_lambda_changed = true;
			_has_changed = vector<bool>(_n,true);
			_x_prev = _x;
			_bad_prev = _bad;
		}
		else if(sgl==Variable::_ACCEPT) {
		}
		else if(sgl==Variable::_REVERT) {
			_x = _x_prev;
			_bad = _bad_prev;
		}
	}
	else if(v==(const Value*)get_quantile()) {
		if(sgl==Variable::_SET) {
			_quantile_changed = true;
			_has_changed = get_quantile()->has_changed();
		}
		else if(sgl==Variable::_PROPOSE) {
			_quantile_changed = true;
			_has_changed = get_quantile()->has_changed();
			_x_prev = _x;
			_bad_prev = _bad;
		}
		else if(sgl==Variable::_ACCEPT) {
		}
		else if(sgl==Variable::_REVERT) {
			_x = _x_prev;
			_bad = _bad_prev;
		}
	}
	// Call default implementation, which is to call Variable::send_signal_to_children(sgl)
	Transformation::receive_signal_from_parent(v,sgl);
}
	
} // namespace gcat

