/*  Copyright 2019 Daniel Wilson.
 *
 *  ContinuousMosaicMixture.h
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
#ifndef _CONTINUOUS_MOSAIC_MIXTURE_DISTRIBUTION_H_
#define _CONTINUOUS_MOSAIC_MIXTURE_DISTRIBUTION_H_
#include <DAG/CompoundDistribution.h>
#include <Variables/Continuous.h>
#include <Variables/ContinuousVector.h>

namespace gcat {

// Forward declaration
class ContinuousMosaicRV;

class ContinuousMosaicMixtureDistribution : public ContinuousVariable, public CompoundDistribution {
protected:
	// Internal used with the get_double() method
	double _x;
	// Flag (one for each child RV) to insist on re-calculation of the full likelihood, e.g. if the parent Parameter or Distribution changes
	bool _calculate_likelihood;
public:
	// Constructor
	ContinuousMosaicMixtureDistribution(string name="", DAG* dag=0);
	// Copy constructor
	ContinuousMosaicMixtureDistribution(const ContinuousMosaicMixtureDistribution& x);
	
	// Implementation of virtual function inherited from base class Distribution
	bool check_random_variable_type(RandomVariable* random_variable);
	// Implementation of virtual function inherited from base class DependentVariable
	bool check_parameter_type(const int i, Variable* parameter);
	void set_p(ContinuousVectorVariable* p);
    void set_m(ContinuousVectorVariable* m);
    ContinuousVectorVariable const* get_p() const;
    ContinuousVectorVariable const* get_m() const;
	Distribution* get_marginal_distribution();
	
	// Compute likelihood
	mydouble likelihood(const RandomVariable* rv, const Value* val);
	mydouble full_likelihood(const ContinuousMosaicRV& y);
	mydouble partial_likelihood_change_value(const ContinuousMosaicRV& y);
	mydouble partial_likelihood_extend_block(const ContinuousMosaicRV& y);
	mydouble partial_likelihood_merge_blocks(const ContinuousMosaicRV& y);
	mydouble partial_likelihood_split_block(const ContinuousMosaicRV& y);
	// Necessary for likelihood: implementation of inherited virtual function
	double get_double() const;
	
	// Overload signalling function inherited via CompoundDistribution from RandomVariable
	void receive_signal_from_parent(const Distribution* dist, const Signal sgl);
	// Overload signalling functions inherited from Distribution
	void receive_signal_from_parent(const Value* v, const Variable::Signal sgl);
};
	
} // namespace gcat

#endif // _CONTINUOUS_MOSAIC_MIXTURE_DISTRIBUTION_H_
