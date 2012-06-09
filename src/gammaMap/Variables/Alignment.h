/*  Copyright 2012 Daniel Wilson.
 *
 *  Alignment.h
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
#ifndef _ALIGNMENT_VARIABLE_H_
#define _ALIGNMENT_VARIABLE_H_
#include <DAG/Value.h>
#include <vector>
#include <myerror.h>
#include <Properties/Length.h>

using std::vector;

using namespace gcat;

namespace gcat_gammaMap {
	
class Alignment : public Value, public LengthProperty {
public:
	// Constructor
	Alignment() {};
	// Copy constructor
	Alignment(const Alignment &x) {};
	// Destructor
	virtual ~Alignment() {};
	
	// Report encoding
	virtual vector<string> encoding() const = 0;
	// Number of sequences
	virtual int n() const = 0;
	// Sequence length. Inherited from LengthProperty
	//virtual int length() const = 0;
	// Return a site
	virtual int seq(const int i, const int j) const = 0;
	// Return an encoded sequence
	virtual const vector<int>& seq(const int i) const = 0;
	// Operator
	virtual const vector<int>& operator[](const int i) const = 0;
	// Return all sequences
	virtual const vector< vector<int> >& seqs() const = 0;
	// Return a label
	virtual string label(const int i) const = 0;
	// Return all labels
	virtual const vector<string>& labels() const = 0;
	
	// Print header (implementation of inherited method)
	virtual void print_header(ostream& out, string sep) {
		myutils::warning("Alignment::print_header(): no print method available");
	}
	// Print value (implementation of inherited method)	
	virtual void print(ostream& out, string sep) {
	}
};
	
} // namespace gcat_gammaMap

#endif // _ALIGNMENT_H_