/*  Copyright 2012 Daniel Wilson.
 *
 *  gcatLibrary.h
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
#ifndef _GCAT_LIBRARY_H_
#define _GCAT_LIBRARY_H_
#include <DAG/DAG.h>

// Standard name that gcat looks for when loading the dynamic library
extern "C" gcat::xsd_string load_gcat_library();

#endif // _GCAT_LIBRARY_H_

