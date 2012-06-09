/*  Copyright 2012 Daniel Wilson.
 *
 *  ContinuousMosaicNumBlocks.h
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
#ifndef _CONTINUOUS_MOSAIC_NUM_BLOCKS_H_
#define _CONTINUOUS_MOSAIC_NUM_BLOCKS_H_
#include <DAG/Transformation.h>
#include <Variables/Discrete.h>
#include <Variables/ContinuousMosaic.h>

namespace gcat {

class ContinuousMosaicNumBlocks : public DiscreteVariable, public Transformation {
public:
	// Constructor
	ContinuousMosaicNumBlocks(string name="", DAG* dag=0);
	// Copy constructor
	ContinuousMosaicNumBlocks(const ContinuousMosaicNumBlocks& x);

	// Implementation of virtual functions inherited from base classes
	int get_int() const;
	bool check_parameter_type(const int i, Variable* parameter);
	
	// Convenience functions
	void set_continuous_mosaic(ContinuousMosaicVariable* mosaic);
	ContinuousMosaicVariable const* get_continuous_mosaic() const;
};
	
} // namespace gcat

#endif //  _CONTINUOUS_MOSAIC_NUM_BLOCKS_H_
