/*  Copyright 2012 Daniel Wilson.
 *
 *  gammaMapXML.cpp
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
#include <gsl/gsl_errno.h>
#include <RandomVariables/Continuous.h>
#include <RandomVariables/ContinuousVector.h>
#include <Distributions/DistributionsXML.h>
#include <RandomVariables/RandomVariablesXML.h>
#include <Transformations/TransformationsXML.h>
#include <Inference/InferenceXML.h>
#include <gammaMap/gammaMapXML.h>
#include <gammaMap/Distributions/Codon61SequenceStationaryDistribution.h>
#include <gammaMap/Distributions/gammaMapHMMHybrid.h>
#include <gammaMap/RandomVariables/Codon61Count.h>
#include <gammaMap/RandomVariables/Codon61Sequence.h>
#include <gammaMap/Inference/MCMC/gammaMapMoves.h>
#include <gammaMap/gammaMap1.0.xsd.h>
#include <stdexcept>

using namespace gcat;

namespace gcat_gammaMap {

// DISTRIBUTIONS

codon61_sequence_stationary_distribution_XMLParser::codon61_sequence_stationary_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<codon61_sequence_stationary_distribution_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 2;
	const char* attrNames[nattr] = {"id","pi"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	new Codon61SequenceStationaryDistribution(sattr[0],getDAG());
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[1],sattr[1]);
}

gammaMapHMMHybrid_XMLParser::gammaMapHMMHybrid_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<gammaMapHMMHybrid_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 11;
	const char* attrNames[nattr] = {"id","anc","theta","kappa","gamma1","T","p","pi","gamma1_wt","gamma2","gamma2_wt"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// theta, kappa, t and p can be specified as numeric, in which case they must be instantiated as Variables
	double double_theta;
	if(from_string<double>(double_theta,sattr[2])) {
		// Internally-generated name
		sattr[2] = "_" + sattr[0] + "." + attrNames[2];
		new ContinuousRV(sattr[2],getDAG(),double_theta);
		getDAG()->set_constant(sattr[2]);
	}
	double double_kappa;
	if(from_string<double>(double_kappa,sattr[3])) {
		// Internally-generated name
		sattr[3] = "_" + sattr[0] + "." + attrNames[3];
		new ContinuousRV(sattr[3],getDAG(),double_kappa);
		getDAG()->set_constant(sattr[3]);
	}
	double double_T;
	if(from_string<double>(double_T,sattr[5])) {
		// Internally-generated name
		sattr[5] = "_" + sattr[0] + "." + attrNames[5];
		new ContinuousRV(sattr[5],getDAG(),double_T);
		getDAG()->set_constant(sattr[5]);
	}
	double double_p;
	if(from_string<double>(double_p,sattr[6])) {
		// Internally-generated name
		sattr[6] = "_" + sattr[0] + "." + attrNames[6];
		new ContinuousRV(sattr[6],getDAG(),double_p);
		getDAG()->set_constant(sattr[6]);
	}
	// Get lengths of anc and gamma
	Parameter* rv = getDAG()->get_parameter(sattr[1]);
	if(rv==0) error("gammaMapHMMHybrid_XMLParser: could not find anc variable");
	LengthProperty* lp = dynamic_cast<LengthProperty*>(rv);
	if(lp==0) error("gammaMapHMMHybrid_XMLParser: anc variable does not have length property");
	int int_seqlen = lp->length();
	rv = getDAG()->get_parameter(sattr[4]);
	if(rv==0) error("gammaMapHMMHybrid_XMLParser: could not find gamma1 variable");
	lp = dynamic_cast<LengthProperty*>(rv);
	if(lp==0) error("gammaMapHMMHybrid_XMLParser: gamma1 variable does not have length property");
	int int_ngamma1 = lp->length();
	rv = getDAG()->get_parameter(sattr[9]);
	if(rv==0) error("gammaMapHMMHybrid_XMLParser: could not find gamma2 variable");
	lp = dynamic_cast<LengthProperty*>(rv);
	if(lp==0) error("gammaMapHMMHybrid_XMLParser: gamma2 variable does not have length property");
	int int_ngamma2 = lp->length();
	// gamma1_wt can take the value 1, in which case it is a vector of 1s
	if(sattr[8]=="1") {
		sattr[8] = "_" + sattr[0] + "." + attrNames[8];
		new ContinuousVectorRV(int_ngamma1,sattr[8],getDAG(),vector<double>(int_ngamma1,1.0));
	}
	else {
		rv = getDAG()->get_parameter(sattr[8]);
		if(rv==0) error("gammaMapHMMHybrid_XMLParser: could not find gamma_wt variable");
		lp = dynamic_cast<LengthProperty*>(rv);
		if(lp==0) error("gammaMapHMMHybrid_XMLParser: gamma1_wt variable does not have length property");
		if(lp->length()!=int_ngamma1) error("gammaMapHMM_XMLParser: gamma1_wt variable has different length to gamma1");
	}
	// gamma2_wt can take the value 1, in which case it is a vector of 1s
	if(sattr[10]=="1") {
		sattr[10] = "_" + sattr[0] + "." + attrNames[10];
		new ContinuousVectorRV(int_ngamma2,sattr[10],getDAG(),vector<double>(int_ngamma2,1.0));
	}
	else {
		rv = getDAG()->get_parameter(sattr[10]);
		if(rv==0) error("gammaMapHMMHybrid_XMLParser: could not find gamma_wt variable");
		lp = dynamic_cast<LengthProperty*>(rv);
		if(lp==0) error("gammaMapHMMHybrid_XMLParser: gamma2_wt variable does not have length property");
		if(lp->length()!=int_ngamma2) error("gammaMapHMM_XMLParser: gamma2_wt variable has different length to gamma2");
	}
	new gammaMapHMMHybrid(int_seqlen,int_ngamma1,int_ngamma2,sattr[0],getDAG());
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[1],sattr[1]);
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[2],sattr[2]);
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[3],sattr[3]);
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[4],sattr[4]);
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[5],sattr[5]);
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[6],sattr[6]);
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[7],sattr[7]);
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[8],sattr[8]);
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[9],sattr[9]);
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[10],sattr[10]);
}

// RANDOM VARIABLES

codon_count_XMLParser::codon_count_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<codon_count_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 5;
	const char* attrNames[nattr] = {"id","distribution","file","format","encoding"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	if(sattr[3]!="fasta") error("codon_count_XMLParser: only fasta format supported");
	// Instantiate the variable
	if(sattr[4]=="codon61") {
		new Codon61Count(sattr[2],sattr[0],getDAG());
	}
	else error("codon_count_XMLParser only codon61 encoding supported");
	if(sattr[1]!="") getDAG()->assign_distribution_to_random_variable(sattr[0],attrNames[1],sattr[1]);
	getDAG()->set_constant(sattr[0]);
}

codon_sequence_XMLParser::codon_sequence_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<codon_sequence_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"id","distribution","encoding"};
	sattr = attributesToStrings(nattr,attrNames,attrs);
	if(sattr[2]!="codon61") error("codon_sequence_XMLParser: currently encoding must equal \"codon61\"");
	// Don't instantiate the variable until the values have been read in
}

void codon_sequence_XMLParser::implement_characters(const XMLCh* const chars, const XMLSize_t length) {
	string message = "";
	int i;
	for(i=0;i<length;i++) message += chars[i];
	istringstream oss(message);
	vector<string> val(0);
	string val_j;
	while(!(oss >> val_j).fail()) {
		val.push_back(val_j);
	}
	if(val.size()==0) error("codon_sequence_XMLParser: no values entered");
	// Are they entered as strings or ints?
	vector<int> ival(val.size());
	if(from_string<int>(ival[0],val[0])) {
		for(i=1;i<val.size();i++) {
			if(!from_string<int>(ival[i],val[i])) {
				error("codon_sequence_XMLParser: mixed integers and strings entered");
			}
		}
		new Codon61SequenceRV(val.size(),sattr[0],getDAG(),ival);
	}
	else {
		new Codon61SequenceRV(val.size(),sattr[0],getDAG(),vector<int>(0),val);
	}
	if(sattr[1]!="") getDAG()->assign_distribution_to_random_variable(sattr[0],"distribution",sattr[1]);
}

// TRANSFORMATIONS

gammaMapHMMHybrid_path_sampler_XMLParser::gammaMapHMMHybrid_path_sampler_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<gammaMapHMMHybrid_path_sampler_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"id","distribution","rv"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	new gammaMapHMMHybridPathSampler(sattr[2],sattr[1],sattr[0],getDAG());
}

// INFERENCE

codon61_sequence_gibbs_sampler_XMLParser::codon61_sequence_gibbs_sampler_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<codon61_sequence_gibbs_sampler_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 2;
	const char* attrNames[nattr] = {"parameter","weight"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	vector<string> target(1,sattr[0]);
	double double_weight;
	if(!from_string<double>(double_weight,sattr[1])) error("codon61_sequence_gibbs_sampler_XMLParser: cannot convert parameter weight to double");
	// Get _mcmc from parent parser via dynamic type-checking
	MCMC_XMLParser* MCMC_XMLParser_parent_parser = dynamic_cast<MCMC_XMLParser*>(parent_parser);
	if(!MCMC_XMLParser_parent_parser) error("codon61_sequence_gibbs_sampler_XMLParser: parent parser must be of type MCMC_XMLParser");
	_mcmc = MCMC_XMLParser_parent_parser->get_mcmc();
	new Codon61SequenceGibbsSampler(_mcmc,target,double_weight);
}

int _OMEGAMAP_LIBRARY_IS_LOADED = 0;

xsd_string load_gammaMap_library() {
	if(_OMEGAMAP_LIBRARY_IS_LOADED!=0) {
		throw std::runtime_error("load_gammaMap_library(): library already loaded");
	} else {
		_OMEGAMAP_LIBRARY_IS_LOADED = 1;
	}
	// GSL is used, so must set this
	gsl_set_error_handler_off();
	// DISTRIBUTIONS
	distributions_XMLParser::add_child("codon61_sequence_stationary_distribution",&codon61_sequence_stationary_distribution_XMLParser::factory);
	distributions_XMLParser::add_child("gammaMapHMMHybrid",&gammaMapHMMHybrid_XMLParser::factory);
	// RANDOM VARIABLES
	data_XMLParser::add_child("codon_count",&codon_count_XMLParser::factory);
	data_XMLParser::add_child("codon_sequence",&codon_sequence_XMLParser::factory);
	parameters_XMLParser::add_child("codon_count",&codon_count_XMLParser::factory);
	parameters_XMLParser::add_child("codon_sequence",&codon_sequence_XMLParser::factory);
	// TRANSFORMATIONS
	transformations_XMLParser::add_child("gammaMapHMMHybrid_path_sampler",&gammaMapHMMHybrid_path_sampler_XMLParser::factory);
	// INFERENCE
	MCMC_XMLParser::add_child("codon61_sequence_gibbs_sampler",&codon61_sequence_gibbs_sampler_XMLParser::factory);
	// SCHEMA
	string s(gammaMap1_0_xsd_len,' ');
	unsigned int i;
	for(i=0;i<gammaMap1_0_xsd_len;i++) s[i] = gammaMap1_0_xsd[i];
	return s;
}

} // namespace gcat_gammaMap
