 /*  Copyright 2012 Daniel Wilson.
 *
 *  gammaMapMoves.h
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
#ifndef _GAMMAMAP_MCMC_MOVES_H_
#define _GAMMAMAP_MCMC_MOVES_H_
#include <Inference/MCMC/MCMC.h>

using namespace gcat;

namespace gcat_gammaMap {
	
class Codon61SequenceGibbsSampler : public MCMC_move {
public:
	// Constructor
	Codon61SequenceGibbsSampler(MCMC* mcmc, vector< std::string > &target, const double weight, std::string type="Codon61SequenceGibbsSampler_move");
	// Go!!!
	void go();
};
	
} // namespace gcat_gammaMap


#endif // _GAMMAMAP_MCMC_MOVES_H_
