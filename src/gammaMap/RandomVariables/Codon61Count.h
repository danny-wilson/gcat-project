/*  Copyright 2012 Daniel Wilson.
 *
 *  Codon61Count.h
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
#ifndef _CODON_61_COUNT_H_
#define _CODON_61_COUNT_H_
#include <gammaMap/Variables/AlleleCount.h>
#include <DAG/RandomVariable.h>
#include <DNA.h>

using namespace gcat;

namespace gcat_gammaMap {
	
class Codon61Count : public AlleleCount, public RandomVariable {
private:
	string _filename;
	int _n;
	int _length;
	// NB:- rows are sites, columns are sequences
	vector< vector<int> > _ct;

public:
	// Constructor
	Codon61Count(string filename, string name="", DAG* dag=0);
	// Copy constructor
	Codon61Count(const Codon61Count& x);
	// Destructor
	virtual ~Codon61Count();
	
	// Implementation of inherited methods
	// Report encoding
	vector<string> encoding() const;
	// Number of sequences
	int n() const;
	// Sequence length
	int length() const;
	// Return the counts for a particular site
	inline const vector<int>& operator[](const int site) const;
	
protected:
	void tally(DNA& dna, const int offset=0);
};

const vector<int>& Codon61Count::operator[](const int site) const {
	return _ct[site];
}	
	
} // namespace gcat_gammaMap

#endif // _CODON_61_ALIGNMENT_H_
