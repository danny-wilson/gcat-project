/*  Copyright 2012 Daniel Wilson.
 *
 *  ContinuousMosaic.cpp
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
#include <RandomVariables/ContinuousMosaic.h>

namespace gcat {

ContinuousMosaicRV::ContinuousMosaicRV(const int n, string name, DAG* dag, vector<int> boundaries, vector<double> values) :
DAGcomponent(name,dag,"ContinuousMosaicRV"), RandomVariable(), _n(n), _nblocks(boundaries.size()), _block_start(vector<int>(_n)), 
_previous_block_start(vector<int>(_n)), _block_end(vector<int>(_n)), _previous_block_end(vector<int>(_n)), _value(vector<double>(_n)), 
_previous_value(vector<double>(_n)), _last_move(NO_CHANGE), _has_changed(_n,true) {
	if(boundaries.size()!=values.size()) error("ContinuousMosaicRV(): number of boundaries must equal number of values");
    if(boundaries[0]!=0) {
        if(boundaries[0]==-1 && boundaries.size()==1) {
            boundaries = vector<int>(n);
            for(int i=0;i<n;i++) boundaries[i] = i;
            values = vector<double>(n,values[0]);
        } else {
            error("ContinuousMosaicRV(): first boundary must be at zero");
        }
    }
	// Initialize _block_start
	int bix = 0, pos;
	int next_boundary = boundaries[bix];
	int block_start = -1;
	for(pos=0;pos<length();pos++) {
		if(pos==next_boundary) {
			block_start = pos;
			next_boundary = (bix<boundaries.size()-1) ? boundaries[bix+1] : length();
			if(next_boundary<=pos) error("ContinuousMosaicRV(): boundaries must be in strict ascending order");
			++bix;
		}
		_block_start[pos] = block_start;
	}
	if(bix!=nblocks()) error("ContinuousMosaicRV(): boundaries exceed mosaic length");
	// Initialize _block_end
	bix = nblocks()-1;
	next_boundary = boundaries[bix];
	int block_end = length()-1;
	for(pos=length()-1;pos>=0;pos--) {
		if(pos<next_boundary) {
			block_end = pos;
			next_boundary = (bix>=0) ? boundaries[bix-1] : -1;
			--bix;
		}
		_block_end[pos] = block_end;
	}
	// Initialize _value
	bix = -1;
	double x;
	for(pos=0;pos<length();pos++) {
		if(pos==_block_start[pos]) {
			++bix;
			x = values[bix];
		}
		_value[pos] = x;
	}
}

ContinuousMosaicRV::ContinuousMosaicRV(const ContinuousMosaicRV& x) : DAGcomponent((const DAGcomponent&)x), RandomVariable((const RandomVariable&)x),
_n(x._n), _nblocks(x._nblocks), _block_start(x._block_start), _previous_block_start(x._previous_block_start), _block_end(x._block_end),
_previous_block_end(x._previous_block_end), _value(x._value), _previous_value(x._previous_value), _last_move(x._last_move), _last_change_value(x._last_change_value),
_last_extend_block(x._last_extend_block), _last_merge_blocks(x._last_merge_blocks), _last_split_block(x._last_split_block), _has_changed(x._has_changed)
{
}

ContinuousMosaicRV::~ContinuousMosaicRV() {};

void ContinuousMosaicRV::change_value(ChangeValue& move, Variable::Signal sgl) {
	int pos = block_start(move.position);
	if(sgl==Variable::_SET || sgl==Variable::_PROPOSE) {
		_last_move = CHANGE_VALUE;
		_last_change_value = move;
		_value[pos] = move.to;
		int i;
		for(i=pos;i<=block_end(pos);i++) {
			_has_changed[i] = true;
		}
	}
	else if(sgl==Variable::_ACCEPT) {
		if(_last_move!=CHANGE_VALUE) error("ContinuousMosaicRV::change_value(): inconsistency in move");
		_last_move = NO_CHANGE;
		_has_changed = vector<bool>(_n,false);
	}
	else if(sgl==Variable::_REVERT) {
		if(_last_move!=CHANGE_VALUE) error("ContinuousMosaicRV::change_value(): inconsistency in move");
		_last_move = NO_CHANGE;
		_value[pos] = move.from;
		_has_changed = vector<bool>(_n,false);
	}
	else {
		error("ContinuousMosaicRV::change_value(): unexpected Variable signal");
	}
	act_on_signal(sgl);
	send_signal_to_children(sgl);
}

void ContinuousMosaicRV::extend_block(ExtendBlock& move, Variable::Signal sgl) {
	if(sgl==Variable::_SET || sgl==Variable::_PROPOSE) {
		_last_move = EXTEND_BLOCK;
		_last_extend_block = move;
		implement_extend_block(move.old_block_start,move.new_block_start);
	}
	else if(sgl==Variable::_ACCEPT) {
		if(_last_move!=EXTEND_BLOCK) error("ContinuousMosaicRV::extend_block(): inconsistency in move");
		_last_move = NO_CHANGE;
		_has_changed = vector<bool>(_n,false);
	}
	else if(sgl==Variable::_REVERT) {
		if(_last_move!=EXTEND_BLOCK) error("ContinuousMosaicRV::extend_block(): inconsistency in move");
		_last_move = NO_CHANGE;
		implement_extend_block(move.new_block_start,move.old_block_start);
		_has_changed = vector<bool>(_n,false);
	}
	else {
		error("ContinuousMosaicRV::extend_block(): unexpected Variable signal");
	}
	act_on_signal(sgl);
	send_signal_to_children(sgl);
}

void ContinuousMosaicRV::merge_blocks(MergeBlocks& move, Variable::Signal sgl) {
	if(sgl==Variable::_SET || sgl==Variable::_PROPOSE) {
		_last_move = MERGE_BLOCKS;
		_last_merge_blocks = move;
		implement_merge_blocks(move.right_block_start,move.to);
	}
	else if(sgl==Variable::_ACCEPT) {
		if(_last_move!=MERGE_BLOCKS) error("ContinuousMosaicRV::merge_blocks(): inconsistency in move");
		_last_move = NO_CHANGE;
		_has_changed = vector<bool>(_n,false);
	}
	else if(sgl==Variable::_REVERT) {
		if(_last_move!=MERGE_BLOCKS) error("ContinuousMosaicRV::merge_blocks(): inconsistency in move");
		_last_move = NO_CHANGE;
		implement_split_block(move.right_block_start,move.from);
		_has_changed = vector<bool>(_n,false);
	}
	else {
		error("ContinuousMosaicRV::merge_blocks(): unexpected Variable signal");
	}
	act_on_signal(sgl);
	send_signal_to_children(sgl);
}

void ContinuousMosaicRV::split_block(SplitBlock& move, Variable::Signal sgl) {
	if(sgl==Variable::_SET || sgl==Variable::_PROPOSE) {
		_last_move = SPLIT_BLOCK;
		_last_split_block = move;
		implement_split_block(move.right_block_start,move.to);
	}
	else if(sgl==Variable::_ACCEPT) {
		if(_last_move!=SPLIT_BLOCK) error("ContinuousMosaicRV::split_block(): inconsistency in move");
		_last_move = NO_CHANGE;
		_has_changed = vector<bool>(_n,false);
	}
	else if(sgl==Variable::_REVERT) {
		if(_last_move!=SPLIT_BLOCK) error("ContinuousMosaicRV::split_block(): inconsistency in move");
		_last_move = NO_CHANGE;
		implement_merge_blocks(move.right_block_start,move.from);
		_has_changed = vector<bool>(_n,false);
	}
	else {
		error("ContinuousMosaicRV::split_block(): unexpected Variable signal");
	}
	act_on_signal(sgl);
	send_signal_to_children(sgl);
}

ContinuousMosaicRV::ContinuousMosaicMoveType ContinuousMosaicRV::last_move() const {
	return _last_move;
}

const ContinuousMosaicRV::ChangeValue& ContinuousMosaicRV::last_change_value() const {
	return _last_change_value;
}

const ContinuousMosaicRV::ExtendBlock& ContinuousMosaicRV::last_extend_block() const {
	return _last_extend_block;
}

const ContinuousMosaicRV::MergeBlocks& ContinuousMosaicRV::last_merge_blocks() const {
	return _last_merge_blocks;
}

const ContinuousMosaicRV::SplitBlock& ContinuousMosaicRV::last_split_block() const {
	return _last_split_block;
}

int ContinuousMosaicRV::length() const {
	return _n;
}

int ContinuousMosaicRV::nblocks() const {
	return _nblocks;
}

double ContinuousMosaicRV::get_double(const int i) const {
	const int pos = _block_start[i];
	return _value[pos];
}

vector<double> ContinuousMosaicRV::get_doubles() const {
	vector<double> v(_n);
	int i;
	for(i=0;i<_n;i++) {
		v[i] = get_double(i);
	}
	return v;
}

bool ContinuousMosaicRV::has_changed(const int i) const {
	return _has_changed[i];
}

vector<bool> ContinuousMosaicRV::has_changed() const {
	return _has_changed;
}

bool ContinuousMosaicRV::is_block_start(const int i) const {
	return (i==_block_start[i]);
}

bool ContinuousMosaicRV::is_block_end(const int i) const {
	return (i==_block_end[i]);
}

int ContinuousMosaicRV::block_start(const int i) const {
	return _block_start[i];
}

int ContinuousMosaicRV::block_end(const int i) const {
	return _block_end[i];
}

void ContinuousMosaicRV::implement_extend_block(const int old_block_start, const int new_block_start) {
	if(block_start(old_block_start)!=old_block_start) error("ContinuousMosaicRV::implement_extend_block(): block does not start at old_block_start");
	if(old_block_start==0) error("ContinuousMosaicRV::implement_extend_block(): cannot left-extend the leftmost block");
	const int leftmost = block_start(old_block_start-1)+1;
	const int rightmost = block_end(old_block_start);
	if(new_block_start<leftmost || new_block_start>rightmost) error("ContinuousMosaicRV::implement_extend_block(): extension out of range");
	int i;
	// Update _value
	_value[new_block_start] = _value[old_block_start];
	// Update _block_start and _block_end
	if(old_block_start<new_block_start) {
		// Rightwards move
		for(i=leftmost-1;i<new_block_start;i++) {
			_block_end[i] = new_block_start-1;
		}
		for(i=old_block_start;i<new_block_start;i++) {
			_block_start[i] = leftmost-1;
			_has_changed[i] = true;
		}
		// On a right move, define as having changed the first value occurring at the start
		// of the right block (even though it hasn't)
		_has_changed[new_block_start] = true;
		for(i=new_block_start;i<=rightmost;i++) {
			_block_start[i] = new_block_start;
		}
	}
	else if(old_block_start>new_block_start) {
		// Leftwards move
		for(i=leftmost-1;i<new_block_start;i++) {
			_block_end[i] = new_block_start-1;
		}
		// Changed 9:42 15/09/2009
		//for(i=new_block_start;i<=old_block_start;i++) {
		for(i=new_block_start;i<old_block_start;i++) {
			_block_end[i] = rightmost;
			_has_changed[i] = true;
		}
		for(i=new_block_start;i<=rightmost;i++) {
			_block_start[i] = new_block_start;
		}
	}
}

void ContinuousMosaicRV::implement_merge_blocks(const int right_block_start, const double to) {
	if(block_start(right_block_start)!=right_block_start) error("ContinuousMosaicRV::implement_merge_blocks(): right block does not start at right_block_start");
	if(right_block_start==0) error("ContinuousMosaicRV::implement_merge_blocks(): cannot left-merge the leftmost block");
	const int left_block_start = block_start(right_block_start-1);
	// Update _value
	_value[left_block_start] = to;
	// Update _block_start and _block_end
	int i;
	const int merged_block_end = block_end(right_block_start);
	for(i=left_block_start;i<right_block_start;i++) {
		_block_end[i] = merged_block_end;
		_has_changed[i] = true;
	}
	for(;i<=merged_block_end;i++) {
		_block_start[i] = left_block_start;
		_has_changed[i] = true;
	}
	--_nblocks;
}

void ContinuousMosaicRV::implement_split_block(const int right_block_start, const double to[2]) {
	const int left_block_start = block_start(right_block_start);
	if(left_block_start==right_block_start) error("ContinuousMosaicRV::implement_split_block(): left block starts at right_block_start");
	// Update _value
	_value[left_block_start] = to[0];
	_value[right_block_start] = to[1];
	// Update _block_start and _block_end
	int i;
	const int right_block_end = block_end(right_block_start);
	for(i=left_block_start;i<right_block_start;i++) {
		_block_end[i] = right_block_start-1;
		_has_changed[i] = true;
	}
	for(;i<=right_block_end;i++) {
		_block_start[i] = right_block_start;
		_has_changed[i] = true;
	}
	++_nblocks;
}
	
} // namespace gcat
