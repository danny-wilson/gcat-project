/*  Copyright 2012 Daniel Wilson.
 *
 *  ContinuousVector.h
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
#ifndef _CONTINUOUS_VECTOR_RANDOM_VARIABLE_H_
#define _CONTINUOUS_VECTOR_RANDOM_VARIABLE_H_
#include <Variables/ContinuousVector.h>
#include <DAG/RandomVariable.h>

namespace gcat {

class ContinuousVectorRV : public ContinuousVectorVariable, public RandomVariable {
private:
	// Length of vector
	int _n;
	// Values
	vector< double > _value, _previous_value;
	// Record whether the values have changed
	vector< bool > _has_changed;
public:
	// Constructor
	ContinuousVectorRV(const int n, string name="", DAG* dag=0, const vector<double> values=vector<double>(1,0.0));
	// Copy constructor
	ContinuousVectorRV(const ContinuousVectorRV& x);
	// Destructor
	virtual ~ContinuousVectorRV();
	
	// Manipulators
	void set(const int i, const double value);
	void set(const vector<double>& value);
	void set(const vector<int>& pos, const vector<double>& value);
	void propose(const int i, const double value);
	void propose(const vector<double>& value);
	void propose(const vector<int>& pos, const vector<double>& value);
	void accept();
	void revert();
	
	// Implementation of inherited methods
	int length() const;
	double get_double(const int i) const;
	vector<double> get_doubles() const;
	bool has_changed(const int i) const;
	vector<bool> has_changed() const;
	
};
	
} // namespace gcat


#endif // _CONTINUOUS_VECTOR_RANDOM_VARIABLE_H_
