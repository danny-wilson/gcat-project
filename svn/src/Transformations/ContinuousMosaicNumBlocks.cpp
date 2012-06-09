/*  Copyright 2012 Daniel Wilson.
 *
 *  ContinuousMosaicNumBlocks.cpp
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
#include <Transformations/ContinuousMosaicNumBlocks.h>

namespace gcat {

const string ContinuousMosaicNumBlocksParameterNames[1] = {"continuous_mosaic"};

ContinuousMosaicNumBlocks::ContinuousMosaicNumBlocks(string name, DAG* dag) : DAGcomponent(name,dag,"ContinuousMosaicNumBlocks"), Transformation(ContinuousMosaicNumBlocksParameterNames,1) {
}

ContinuousMosaicNumBlocks::ContinuousMosaicNumBlocks(const ContinuousMosaicNumBlocks& x) : DAGcomponent(x), Transformation(x) {
}
	
int ContinuousMosaicNumBlocks::get_int() const {
	return get_continuous_mosaic()->nblocks();
}

bool ContinuousMosaicNumBlocks::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		case 0:	// continuous_mosaic
			return(dynamic_cast<ContinuousMosaicVariable*>(parameter));
		default:
			error("ContinuousMosaicNumBlocks::check_parameter_type(): parameter not found");
	}
	return false;
}
	
void ContinuousMosaicNumBlocks::set_continuous_mosaic(ContinuousMosaicVariable* mosaic) {
	set_parameter(0,(Variable*)mosaic);
}

ContinuousMosaicVariable const* ContinuousMosaicNumBlocks::get_continuous_mosaic() const {
	return (ContinuousMosaicVariable const*)get_parameter(0);
}
	
} // namespace gcat

