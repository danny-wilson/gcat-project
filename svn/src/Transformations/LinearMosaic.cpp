/*  Copyright 2012 Daniel Wilson.
 *
 *  LinearMosaic.cpp
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
#include <Transformations/LinearMosaic.h>

namespace gcat {

const string LinearMosaicTransformParameterNames[3] = {"mean","sd","z"};

LinearMosaicTransform::LinearMosaicTransform(const int n, string name, DAG* dag) : DAGcomponent(name,dag,"LinearMosaicTransform"), Transformation(LinearMosaicTransformParameterNames,3), _n(n), _mean_changed(true), _sd_changed(true), _z_changed(true), _x(n), _x_prev(n), _has_changed(n,true), _bad(n), _bad_prev(n) {
}

LinearMosaicTransform::LinearMosaicTransform(const LinearMosaicTransform& x) : DAGcomponent(x), Transformation(x), _n(x._n), _mean_changed(x._mean_changed), _sd_changed(x._sd_changed), _z_changed(x._z_changed), _x(x._x), _x_prev(x._x_prev), _has_changed(x._has_changed), _bad(x._bad), _bad_prev(x._bad_prev)  {
}

int LinearMosaicTransform::length() const {
	return _n;
}

double LinearMosaicTransform::get_double(const int i) const {
	if(_recalculate) recalculate();
	const int pos = block_start(i);
	// Only throw if the value is requested
	if(_bad[pos]) throw BadValueException(to_Value(),"Standard deviation out of range");
	return _x[pos];
}

void LinearMosaicTransform::recalculate() const {
	//	if(_mean_changed || _sd_changed || _z_changed) {
	// Recalculate
	double mean = get_mean()->get_double();
	double sd = get_sd()->get_double();
	if(!sd>0) _bad = vector<bool>(_n,true);
	else {
		int pos;
		for(pos=0;pos<_n;pos++) {
			if(is_block_start(pos)) {		
				double z = get_z()->get_double(pos);
				if(z!=z) _bad[pos] = true;
				else {
					_x[pos] = mean+sd*z;
					_bad[pos] = false;
				}
			}
		}
	}
	_mean_changed = _sd_changed = _z_changed = false;
	//	}
	_recalculate = false;
}

vector<double> LinearMosaicTransform::get_doubles() const {
	vector<double> ret(_n);
	int i;
	for(i=0;i<_n;i++) ret[i] = get_double(i);
	return ret;
}

bool LinearMosaicTransform::has_changed(const int i) const {
	return _has_changed[i];
}

vector<bool> LinearMosaicTransform::has_changed() const {
	return _has_changed;
}

int LinearMosaicTransform::nblocks() const {
	return get_z()->nblocks();
}

bool LinearMosaicTransform::is_block_start(const int i) const {
	return get_z()->is_block_start(i);
}

bool LinearMosaicTransform::is_block_end(const int i) const {
	return get_z()->is_block_end(i);
}

int LinearMosaicTransform::block_start(const int i) const {
	return get_z()->block_start(i);
}

int LinearMosaicTransform::block_end(const int i) const {
	return get_z()->block_end(i);
}

bool LinearMosaicTransform::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		case 0:	// mean
			return(dynamic_cast<ContinuousVariable*>(parameter));
		case 1:	// sd
			return(dynamic_cast<ContinuousVariable*>(parameter));
		case 2:	// z
			return(dynamic_cast<ContinuousMosaicVariable*>(parameter));
		default:
			error("LinearMosaicTransform::check_parameter_type(): parameter not found");
	}
	return false;
}

void LinearMosaicTransform::set_mean(ContinuousVariable* mean) {
	set_parameter(0,(Variable*)mean);
}

void LinearMosaicTransform::set_sd(ContinuousVariable* sd) {
	set_parameter(1,(Variable*)sd);
}

void LinearMosaicTransform::set_z(ContinuousMosaicVariable* z) {
	set_parameter(2,(Variable*)z);
}

ContinuousVariable const* LinearMosaicTransform::get_mean() const {
	return (ContinuousVariable const*)get_parameter(0);
}

ContinuousVariable const* LinearMosaicTransform::get_sd() const {
	return (ContinuousVariable const*)get_parameter(1);
}

ContinuousMosaicVariable const* LinearMosaicTransform::get_z() const {
	return (ContinuousMosaicVariable const*)get_parameter(2);
}

void LinearMosaicTransform::receive_signal_from_parent(const Value* v, const Variable::Signal sgl) {
	if(sgl==Variable::_ACCEPT || sgl==Variable::_REVERT) {
		_mean_changed = _sd_changed = _z_changed = false;
		_has_changed = vector<bool>(_n,false);
	}
	if(sgl==Variable::_SET || sgl==Variable::_PROPOSE) {
		_recalculate = true;
	}
	if(v==(const Value*)get_mean()) {
		if(sgl==Variable::_SET) {
			_mean_changed = true;
			_has_changed = vector<bool>(_n,true);
		}
		else if(sgl==Variable::_PROPOSE) {
			_mean_changed = true;
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
	else if(v==(const Value*)get_sd()) {
		if(sgl==Variable::_SET) {
			_sd_changed = true;
			_has_changed = vector<bool>(_n,true);
		}
		else if(sgl==Variable::_PROPOSE) {
			_sd_changed = true;
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
	else if(v==(const Value*)get_z()) {
		if(sgl==Variable::_SET) {
			_z_changed = true;
			_has_changed = get_z()->has_changed();
		}
		else if(sgl==Variable::_PROPOSE) {
			_z_changed = true;
			_has_changed = get_z()->has_changed();
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

