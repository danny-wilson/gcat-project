/*  Copyright 2012 Daniel Wilson.
 *
 *  AlleleCount.h
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
#ifndef _ALLELE_COUNT_VARIABLE_H_
#define _ALLELE_COUNT_VARIABLE_H_
#include <DAG/Value.h>
#include <vector>
#include <myerror.h>
#include <Properties/Length.h>

using std::vector;

using namespace gcat;

namespace gcat_gammaMap {
	
class AlleleCount : public Value, public LengthProperty {
public:
	// Constructor
	AlleleCount() {};
	// Copy constructor
	AlleleCount(const AlleleCount &x) {};
	// Destructor
	virtual ~AlleleCount() {};
	
	// Report encoding
	virtual vector<string> encoding() const = 0;
	// Number of sequences
	virtual int n() const = 0;
	// Sequence length. Inherited from LengthProperty
	//virtual int length() const = 0;
	// Return the counts for a particular site
	virtual const vector<int>& operator[](const int site) const = 0;
	
	// Print header (implementation of inherited method)
	virtual void print_header(ostream& out, string sep) {
		myutils::warning("AlleleCount::print_header(): no print method available");
	}
	// Print value (implementation of inherited method)	
	virtual void print(ostream& out, string sep) {
	}
};
	
} // namespace gcat_gammaMap

#endif // _ALLELE_COUNT_VARIABLE_H_
