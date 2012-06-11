/*  Copyright 2012 Daniel Wilson.
 *
 *  gammaMapLibrary.cpp
 *  Part of the gammaMap library.
 *
 *  The gammaMap library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  The gammaMap library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU Lesser General Public License for more details.
 *  
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with the gammaMap library. If not, see <http://www.gnu.org/licenses/>.
 */
#include <gammaMap/gammaMapLibrary.h>

extern "C" {
	gcat::xsd_string load_gcat_library() {
		return gcat_gammaMap::load_gammaMap_library();
	}
}

