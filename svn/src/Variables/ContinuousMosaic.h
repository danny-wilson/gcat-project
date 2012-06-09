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
#ifndef _CONTINOUS_MOSAIC_VARIABLE_H_
#define _CONTINOUS_MOSAIC_VARIABLE_H_
#include <Variables/ContinuousVector.h>
#include <string>
#include <ostream>

using std::string;
using std::ostream;

namespace gcat {

// Abstract base class, guarantees methods called get_double(const int i), etc and implements print() methods
class ContinuousMosaicVariable : public ContinuousVectorVariable {
public:
	// Constructor
	ContinuousMosaicVariable() {};
	// Copy constructor
	ContinuousMosaicVariable(const ContinuousMosaicVariable &x) {};
	// Destructor
	virtual ~ContinuousMosaicVariable() {};
	// Get the number of breakpoints
	virtual int nblocks() const = 0;
	// Is there a left breakpoint at position i?
	virtual bool is_block_start(const int i) const = 0;
	// Is there a right breakpoint at position i?
	virtual bool is_block_end(const int i) const = 0;
	// Where is the start of the current block?
	virtual int block_start(const int i) const = 0;
	// Where is the end of the current block?
	virtual int block_end(const int i) const = 0;
};
	
} // namespace gcat

#endif // _CONTINOUS_MOSAIC_VARIABLE_H_

