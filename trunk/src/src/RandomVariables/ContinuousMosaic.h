/*  Copyright 2012 Daniel Wilson.
 *
 *  ContinuousMosaic.h
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
#ifndef _CONTINOUS_MOSAIC_RANDOM_VARIABLE_H_
#define _CONTINOUS_MOSAIC_RANDOM_VARIABLE_H_
#include <Variables/ContinuousMosaic.h>
#include <DAG/RandomVariable.h>

namespace gcat {

class ContinuousMosaicRV : public ContinuousMosaicVariable, public RandomVariable {
public:	// Types of modifications: publicly accessible types
	enum ContinuousMosaicMoveType {NO_CHANGE, CHANGE_VALUE, EXTEND_BLOCK, MERGE_BLOCKS, SPLIT_BLOCK};
	struct ChangeValue {
		int position;
		double from;
		double to;
	};
	struct ExtendBlock {
		int old_block_start;
		int new_block_start;
	};
	struct MergeBlocks {
		int right_block_start;
		double from[2];
		double to;
	};
	struct SplitBlock {
		int right_block_start;
		double from;
		double to[2];
	};

private:
	// Length of mosaic
	int _n;
	// Number of blocks
	int _nblocks;
	// Position of breakpoints: what is the start position of the current block?
	vector< int > _block_start, _previous_block_start;
	// Position of breakpoints: what is the end position of the current block?
	vector< int > _block_end, _previous_block_end;
	// Values of the mosaic
	vector< double > _value, _previous_value;
	// Record whether the values have changed
	vector< bool > _has_changed;
	// Variables to record modifications of various types
	ContinuousMosaicMoveType _last_move;
	ChangeValue _last_change_value;
	ExtendBlock _last_extend_block;
	MergeBlocks _last_merge_blocks;
	SplitBlock _last_split_block;
	
public:
	// Constructor
	ContinuousMosaicRV(const int n, string name="", DAG* dag=0, const vector<int> boundaries=vector<int>(1,1), const vector<double> values=vector<double>(1,0.0));
	// Copy constructor
	ContinuousMosaicRV(const ContinuousMosaicRV& x);
	// Destructor
	virtual ~ContinuousMosaicRV();
	
	// Signal (set/propose/accept/revert) a change in value of a block
	void change_value(ChangeValue& move, Variable::Signal sgl);
	// Signal (set/propose/accept/revert) the extension of a block
	void extend_block(ExtendBlock& move, Variable::Signal sgl);
	// Signal (set/propose/accept/revert) the merging of adjacent blocks
	void merge_blocks(MergeBlocks& move, Variable::Signal sgl);
	// Signal (set/propose/accept/revert) the splitting of a block
	void split_block(SplitBlock& move, Variable::Signal sgl);
	
	// Accessor functions for details of the last modification
	ContinuousMosaicMoveType last_move() const;
	const ChangeValue& last_change_value() const;
	const ExtendBlock& last_extend_block() const;
	const MergeBlocks& last_merge_blocks() const;
	const SplitBlock& last_split_block() const;
	
	// Implementation of inherited methods
	// Get length of the variable
	int length() const;
	// Get the number of blocks (equal to the number of breakpoints+1)
	int nblocks() const;
	// Get value at position i
	double get_double(const int i) const;
	// Get value at position i
	vector<double> get_doubles() const;
	// Has the value changed at position i?
	bool has_changed(const int i) const;
	// Has the value changed at each position?
	vector<bool> has_changed() const;
	// Is there a left breakpoint at position i?
	bool is_block_start(const int i) const;
	// Is there a right breakpoint at position i?
	bool is_block_end(const int i) const;
	// Where is the start of the current block?
	int block_start(const int i) const;
	// Where is the end of the current block?
	int block_end(const int i) const;
	
private:
	void implement_extend_block(const int old_block_start, const int new_block_start);
	void implement_merge_blocks(const int right_block_start, const double to);
	void implement_split_block(const int right_block_start, const double to[2]);
};
	
} // namespace gcat

#endif // _CONTINOUS_MOSAIC_RANDOM_VARIABLE_H_


