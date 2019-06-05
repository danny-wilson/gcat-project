/*  Copyright 2012 Daniel Wilson.
 *
 *  InferenceXML.cpp
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
#include <Inference/InferenceXML.h>

namespace gcat {

continuous_mosaic_extend_block_XMLParser::continuous_mosaic_extend_block_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<continuous_mosaic_extend_block_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"parameter","mean_extension","weight"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	vector<string> target(1,sattr[0]);
	double double_mean_extension;
	if(!from_string<double>(double_mean_extension,sattr[1])) error("continuous_mosaic_extend_block_XMLParser: cannot convert parameter mean_extension to double");
	double double_weight;
	if(!from_string<double>(double_weight,sattr[2])) error("continuous_mosaic_extend_block_XMLParser: cannot convert parameter weight to double");
	
	/******************************
	 
	 NB:-	need to pass all these XML parser object MCMC* rather than DAG* and redefine constructors for the
	 MCMC_move objects to replace the DAG* and Random* pointers with a single MCMC*
	 
	 ******************************/
	
	// Get _mcmc from parent parser via dynamic type-checking
	MCMC_XMLParser* MCMC_XMLParser_parent_parser = dynamic_cast<MCMC_XMLParser*>(parent_parser);
	if(!MCMC_XMLParser_parent_parser) error("continuous_mosaic_extend_block_XMLParser: parent parser must be of type MCMC_XMLParser");
	_mcmc = MCMC_XMLParser_parent_parser->get_mcmc();
	new ContinuousMosaicExtendBlock(_mcmc,target,double_weight,double_mean_extension);
}

continuous_mosaic_log_uniform_proposal_XMLParser::continuous_mosaic_log_uniform_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<continuous_mosaic_log_uniform_proposal_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"parameter","half-width","weight"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	vector<string> target(1,sattr[0]);
	double double_half_width;
	if(!from_string<double>(double_half_width,sattr[1])) error("continuous_mosaic_log_uniform_proposal_XMLParser: cannot convert parameter half-width to double");
	double double_weight;
	if(!from_string<double>(double_weight,sattr[2])) error("continuous_mosaic_log_uniform_proposal_XMLParser: cannot convert parameter weight to double");
	// Get _mcmc from parent parser via dynamic type-checking
	MCMC_XMLParser* MCMC_XMLParser_parent_parser = dynamic_cast<MCMC_XMLParser*>(parent_parser);
	if(!MCMC_XMLParser_parent_parser) error("continuous_mosaic_log_uniform_proposal_XMLParser: parent parser must be of type MCMC_XMLParser");
	_mcmc = MCMC_XMLParser_parent_parser->get_mcmc();
	new ContinuousMosaicLogUniformProposal(_mcmc,target,double_weight,double_half_width);
}

continuous_mosaic_splitmerge_block_XMLParser::continuous_mosaic_splitmerge_block_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<continuous_mosaic_splitmerge_block_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 4;
	const char* attrNames[nattr] = {"parameter","p","weight","mean_type"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	vector<string> target(1,sattr[0]);
	double double_p;
	if(!from_string<double>(double_p,sattr[1])) error("continuous_mosaic_splitmerge_block_XMLParser: cannot convert parameter p to double");
	if(double_p<=0 || double_p>=1) error("continuous_mosaic_splitmerge_block_XMLParser: parameter p must lie between 0 and 1 exclusive");
	double double_weight;
	if(!from_string<double>(double_weight,sattr[2])) error("continuous_mosaic_splitmerge_block_XMLParser: cannot convert parameter weight to double");
	ContinuousMosaicSplitMergeBlock::MeanType mean_type;
	if(sattr[3]=="arithmetic") mean_type = ContinuousMosaicSplitMergeBlock::ARITHMETIC;
	else if(sattr[3]=="geometric") mean_type = ContinuousMosaicSplitMergeBlock::GEOMETRIC;
	else error("continuous_mosaic_splitmerge_block_XMLParser: mean_type must equal \"arithmetic\" or \"geometric\"");
	// Get _mcmc from parent parser via dynamic type-checking
	MCMC_XMLParser* MCMC_XMLParser_parent_parser = dynamic_cast<MCMC_XMLParser*>(parent_parser);
	if(!MCMC_XMLParser_parent_parser) error("continuous_mosaic_splitmerge_block_XMLParser: parent parser must be of type MCMC_XMLParser");
	_mcmc = MCMC_XMLParser_parent_parser->get_mcmc();
	new ContinuousMosaicSplitMergeBlock(_mcmc,target,double_weight,double_p,mean_type);
}

continuous_mosaic_uniform_proposal_XMLParser::continuous_mosaic_uniform_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<continuous_mosaic_uniform_proposal_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"parameter","half-width","weight"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	vector<string> target(1,sattr[0]);
	double double_half_width;
	if(!from_string<double>(double_half_width,sattr[1])) error("continuous_mosaic_uniform_proposal_XMLParser: cannot convert parameter half-width to double");
	double double_weight;
	if(!from_string<double>(double_weight,sattr[2])) error("continuous_mosaic_uniform_proposal_XMLParser: cannot convert parameter weight to double");
	// Get _mcmc from parent parser via dynamic type-checking
	MCMC_XMLParser* MCMC_XMLParser_parent_parser = dynamic_cast<MCMC_XMLParser*>(parent_parser);
	if(!MCMC_XMLParser_parent_parser) error("continuous_mosaic_uniform_proposal_XMLParser: parent parser must be of type MCMC_XMLParser");
	_mcmc = MCMC_XMLParser_parent_parser->get_mcmc();
	new ContinuousMosaicUniformProposal(_mcmc,target,double_weight,double_half_width);
}

	continuous_vector_uniform_proposal_XMLParser::continuous_vector_uniform_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<continuous_vector_uniform_proposal_XMLParser>(master_parser,parent_parser) {
		// Read in the attributes
		const int nattr = 3;
		const char* attrNames[nattr] = {"parameter","half-width","weight"};
		vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
		vector<string> target(1,sattr[0]);
		double double_half_width;
		if(!from_string<double>(double_half_width,sattr[1])) error("continuous_vector_uniform_proposal_XMLParser: cannot convert parameter half-width to double");
		double double_weight;
		if(!from_string<double>(double_weight,sattr[2])) error("continuous_vector_uniform_proposal_XMLParser: cannot convert parameter weight to double");
		// Get _mcmc from parent parser via dynamic type-checking
		MCMC_XMLParser* MCMC_XMLParser_parent_parser = dynamic_cast<MCMC_XMLParser*>(parent_parser);
		if(!MCMC_XMLParser_parent_parser) error("continuous_vector_uniform_proposal_XMLParser: parent parser must be of type MCMC_XMLParser");
		_mcmc = MCMC_XMLParser_parent_parser->get_mcmc();
		new ContinuousVectorJointUniformProposal(_mcmc,target,double_weight,double_half_width);
	}

	continuous_vector_log_uniform_proposal_XMLParser::continuous_vector_log_uniform_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<continuous_vector_log_uniform_proposal_XMLParser>(master_parser,parent_parser) {
		// Read in the attributes
		const int nattr = 3;
		const char* attrNames[nattr] = {"parameter","half-width","weight"};
		vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
		vector<string> target(1,sattr[0]);
		double double_half_width;
		if(!from_string<double>(double_half_width,sattr[1])) error("continuous_vector_log_uniform_proposal_XMLParser: cannot convert parameter half-width to double");
		double double_weight;
		if(!from_string<double>(double_weight,sattr[2])) error("continuous_vector_log_uniform_proposal_XMLParser: cannot convert parameter weight to double");
		// Get _mcmc from parent parser via dynamic type-checking
		MCMC_XMLParser* MCMC_XMLParser_parent_parser = dynamic_cast<MCMC_XMLParser*>(parent_parser);
		if(!MCMC_XMLParser_parent_parser) error("continuous_vector_log_uniform_proposal_XMLParser: parent parser must be of type MCMC_XMLParser");
		_mcmc = MCMC_XMLParser_parent_parser->get_mcmc();
		new ContinuousVectorJointLogUniformProposal(_mcmc,target,double_weight,double_half_width);
	}
	
log_uniform_proposal_XMLParser::log_uniform_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<log_uniform_proposal_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"parameter","half-width","weight"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	vector<string> target(1,sattr[0]);
	double double_half_width;
	if(!from_string<double>(double_half_width,sattr[1])) error("log_uniform_proposal_XMLParser: cannot convert parameter half-width to double");
	double double_weight;
	if(!from_string<double>(double_weight,sattr[2])) error("log_uniform_proposal_XMLParser: cannot convert parameter weight to double");
	// Get _mcmc from parent parser via dynamic type-checking
	MCMC_XMLParser* MCMC_XMLParser_parent_parser = dynamic_cast<MCMC_XMLParser*>(parent_parser);
	if(!MCMC_XMLParser_parent_parser) error("log_uniform_proposal_XMLParser: parent parser must be of type MCMC_XMLParser");
	_mcmc = MCMC_XMLParser_parent_parser->get_mcmc();
	new LogUniformProposal(_mcmc,target,double_weight,double_half_width);
}

logit_uniform_proposal_XMLParser::logit_uniform_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<logit_uniform_proposal_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"parameter","half-width","weight"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	vector<string> target(1,sattr[0]);
	double double_half_width;
	if(!from_string<double>(double_half_width,sattr[1])) error("logit_uniform_proposal_XMLParser: cannot convert parameter half-width to double");
	double double_weight;
	if(!from_string<double>(double_weight,sattr[2])) error("logit_uniform_proposal_XMLParser: cannot convert parameter weight to double");
	// Get _mcmc from parent parser via dynamic type-checking
	MCMC_XMLParser* MCMC_XMLParser_parent_parser = dynamic_cast<MCMC_XMLParser*>(parent_parser);
	if(!MCMC_XMLParser_parent_parser) error("logit_uniform_proposal_XMLParser: parent parser must be of type MCMC_XMLParser");
	_mcmc = MCMC_XMLParser_parent_parser->get_mcmc();
	new LogitUniformProposal(_mcmc,target,double_weight,double_half_width);
}

mpi_adaptive_metropolis_parameters_XMLParser::mpi_adaptive_metropolis_parameters_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<mpi_adaptive_metropolis_parameters_XMLParser>(master_parser,parent_parser) {
	// Get _mcmc from parent parser via dynamic type-checking
	mpi_adaptive_metropolis_XMLParser* mpi_adaptive_metropolis_XMLParser_parent_parser = dynamic_cast<mpi_adaptive_metropolis_XMLParser*>(parent_parser);
	if(!mpi_adaptive_metropolis_XMLParser_parent_parser) error("mpi_adaptive_metropolis_parameters_XMLParser: parent parser must be of type mpi_adaptive_metropolis_XMLParser");
	_mcmc = mpi_adaptive_metropolis_XMLParser_parent_parser->get_mcmc();
}

void mpi_adaptive_metropolis_parameters_XMLParser::implement_characters(const XMLCh* const chars, const XMLSize_t length) {
	string message = "";
	int i;
	for(i=0;i<length;i++) message += chars[i];
	istringstream oss(message);
	((mpi_adaptive_metropolis_XMLParser*)_parent_parser)->target = vector<string>(0);
	string val_j;
	while(!(oss >> val_j).fail()) {
		((mpi_adaptive_metropolis_XMLParser*)_parent_parser)->target.push_back(val_j);
	}
	if(((mpi_adaptive_metropolis_XMLParser*)_parent_parser)->target.size()==0) error("mpi_adaptive_metropolis_parameters_XMLParser: no values entered");
}

mpi_adaptive_metropolis_C0_XMLParser::mpi_adaptive_metropolis_C0_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<mpi_adaptive_metropolis_C0_XMLParser>(master_parser,parent_parser) {
	// Get _mcmc from parent parser via dynamic type-checking
	mpi_adaptive_metropolis_XMLParser* mpi_adaptive_metropolis_XMLParser_parent_parser = dynamic_cast<mpi_adaptive_metropolis_XMLParser*>(parent_parser);
	if(!mpi_adaptive_metropolis_XMLParser_parent_parser) error("mpi_adaptive_metropolis_C0_XMLParser: parent parser must be of type mpi_adaptive_metropolis_XMLParser");
	_mcmc = mpi_adaptive_metropolis_XMLParser_parent_parser->get_mcmc();
}

void mpi_adaptive_metropolis_C0_XMLParser::implement_characters(const XMLCh* const chars, const XMLSize_t length) {
	string message = "";
	int i;
	for(i=0;i<length;i++) message += chars[i];
	istringstream oss(message);
	vector<double> val(0);
	double val_j;
	while(!(oss >> val_j).fail()) {
		val.push_back(val_j);
	}
	if(val.size()==0) error("mpi_adaptive_metropolis_C0_XMLParser: no values entered");
	const int d = ((mpi_adaptive_metropolis_XMLParser*)_parent_parser)->target.size();
	((mpi_adaptive_metropolis_XMLParser*)_parent_parser)->C0 = Matrix<double>(d,d,0);
	if(val.size()==1) {
		int i;
		for(i=0;i<d;i++) ((mpi_adaptive_metropolis_XMLParser*)_parent_parser)->C0[i][i] = val[0];
	}
	else if(val.size()==d) {
		int i;
		for(i=0;i<d;i++) ((mpi_adaptive_metropolis_XMLParser*)_parent_parser)->C0[i][i] = val[i];
	}
	else if(val.size()==d*d) {
		int i,j,ctr;
		for(i=0,ctr=0;i<d;i++) {
			for(j=0;j<d;j++,ctr++) {
				((mpi_adaptive_metropolis_XMLParser*)_parent_parser)->C0[i][j] = val[ctr];
			}
		}
	}
	else error("mpi_adaptive_metropolis_C0_XMLParser: C0 must have length 1, d or d*d, where d is # parameters");
}

mpi_adaptive_metropolis_XMLParser::mpi_adaptive_metropolis_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<mpi_adaptive_metropolis_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 5;
	const char* attrNames[nattr] = {"weight","handshake","epsilon","t0","denom"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	if(!from_string<double>(double_weight,sattr[0])) error("mpi_adaptive_metropolis_XMLParser: cannot convert parameter weight to double");
	if(!from_string<int>(int_handshake,sattr[1])) error("mpi_adaptive_metropolis_XMLParser: cannot convert parameter handshake to int");
	if(!from_string<double>(double_epsilon,sattr[2])) error("mpi_adaptive_metropolis_XMLParser: cannot convert parameter epsilon to double");
	if(!from_string<double>(double_t0,sattr[3])) error("mpi_adaptive_metropolis_XMLParser: cannot convert parameter t0 to double");
	if(!from_string<double>(double_denom,sattr[4])) error("mpi_adaptive_metropolis_XMLParser: cannot convert parameter denom to double");
	// Get _mcmc from parent parser via dynamic type-checking
	MCMC_XMLParser* MCMC_XMLParser_parent_parser = dynamic_cast<MCMC_XMLParser*>(parent_parser);
	if(!MCMC_XMLParser_parent_parser) error("mpi_adaptive_metropolis_XMLParser: parent parser must be of type MCMC_XMLParser");
	_mcmc = MCMC_XMLParser_parent_parser->get_mcmc();
	// Don't instantiate until endElement!
}

void mpi_adaptive_metropolis_XMLParser::implement_startElement(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs) {
	string element = elementName(localname);
	if(element=="parameters") {
		_child_parser = new mpi_adaptive_metropolis_parameters_XMLParser(uri,localname,qname,attrs,_master_parser,this);
	}
	else if(element=="C0") {
		_child_parser = new mpi_adaptive_metropolis_C0_XMLParser(uri,localname,qname,attrs,_master_parser,this);
	}
	else DAGXMLParserTemplate<mpi_adaptive_metropolis_XMLParser>::implement_startElement(uri,localname,qname,attrs);
}

void mpi_adaptive_metropolis_XMLParser::implement_endElement(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname) {
	// Check for symmetric of C0
	int i,j;
	for(i=0;i<C0.nrows();i++) {
		for(j=0;j<i;j++) {
			if(!(C0[i][j]==C0[j][i])) error("mpi_adaptive_metropolis_XMLParser: C0 is not a symmetric matrix");
		}
	}
	// Instantiate!
#ifdef _MPI_WILL_BE_LINKED
	new MPIAdaptiveMetropolis(_mcmc,target,double_weight,int_handshake,double_epsilon,C0,double_t0,double_denom);
#else
	error("mpi_adaptive_metropolis_XMLParser: only available in MPI environment");
#endif
	// Return to default behaviour
	DAGXMLParserTemplate<mpi_adaptive_metropolis_XMLParser>::implement_endElement(uri,localname,qname);
}

mpi_adaptive_metropolis_within_gibbs_XMLParser::mpi_adaptive_metropolis_within_gibbs_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<mpi_adaptive_metropolis_within_gibbs_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 6;
	const char* attrNames[nattr] = {"parameter","delta","batchsize","sd","weight","handshake"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	vector<string> target(1,sattr[0]);
	double double_delta;
	if(!from_string<double>(double_delta,sattr[1])) error("mpi_adaptive_metropolis_within_gibbs_XMLParser: cannot convert parameter delta to double");
	int int_batchsize;
	if(!from_string<int>(int_batchsize,sattr[2])) error("mpi_adaptive_metropolis_within_gibbs_XMLParser: cannot convert parameter batchsize to int");
	double double_sd;
	if(!from_string<double>(double_sd,sattr[3])) error("mpi_adaptive_metropolis_within_gibbs_XMLParser: cannot convert parameter sd to double");
	if(double_sd<=0) error("mpi_adaptive_metropolis_within_gibbs_XMLParser: parameter sd must be positive");
	double double_weight;
	if(!from_string<double>(double_weight,sattr[4])) error("mpi_adaptive_metropolis_within_gibbs_XMLParser: cannot convert parameter weight to double");
	int int_handshake;
	if(!from_string<int>(int_handshake,sattr[5])) error("mpi_adaptive_metropolis_within_gibbs_XMLParser: cannot convert parameter handshake to int");
	// Get _mcmc from parent parser via dynamic type-checking
	MCMC_XMLParser* MCMC_XMLParser_parent_parser = dynamic_cast<MCMC_XMLParser*>(parent_parser);
	if(!MCMC_XMLParser_parent_parser) error("mpi_adaptive_metropolis_within_gibbs_XMLParser: parent parser must be of type MCMC_XMLParser");
	_mcmc = MCMC_XMLParser_parent_parser->get_mcmc();
#ifdef _MPI_WILL_BE_LINKED
	double double_lsd = log(double_sd);
	new MPIAdaptiveMetropolisWithinGibbs(_mcmc,target,double_weight,int_handshake,double_delta,int_batchsize,double_lsd);
#else
	error("mpi_adaptive_metropolis_within_gibbs_XMLParser: only available in MPI environment");
#endif
}

mpi_log_normal_proposal_XMLParser::mpi_log_normal_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<mpi_log_normal_proposal_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 4;
	const char* attrNames[nattr] = {"parameter","sd","weight","handshake"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	vector<string> target(1,sattr[0]);
	double double_sd;
	if(!from_string<double>(double_sd,sattr[1])) error("mpi_log_normal_proposal_XMLParser: cannot convert parameter sd to double");
	double double_weight;
	if(!from_string<double>(double_weight,sattr[2])) error("mpi_log_normal_proposal_XMLParser: cannot convert parameter weight to double");
	int int_handshake;
	if(!from_string<int>(int_handshake,sattr[3])) error("mpi_log_normal_proposal_XMLParser: cannot convert parameter handshake to int");
	// Get _mcmc from parent parser via dynamic type-checking
	MCMC_XMLParser* MCMC_XMLParser_parent_parser = dynamic_cast<MCMC_XMLParser*>(parent_parser);
	if(!MCMC_XMLParser_parent_parser) error("mpi_log_normal_proposal_XMLParser: parent parser must be of type MCMC_XMLParser");
	_mcmc = MCMC_XMLParser_parent_parser->get_mcmc();
#ifdef _MPI_WILL_BE_LINKED
	new MPILogNormalProposal(_mcmc,target,double_weight,int_handshake,double_sd);
#else
	error("mpi_log_normal_proposal_XMLParser: only available in MPI environment");
#endif
}

mpi_log_normal_sync_proposal_XMLParser::mpi_log_normal_sync_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<mpi_log_normal_sync_proposal_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"sd","weight","handshake"};
	sattr = attributesToStrings(nattr,attrNames,attrs);
	// Get _mcmc from parent parser via dynamic type-checking
	MCMC_XMLParser* MCMC_XMLParser_parent_parser = dynamic_cast<MCMC_XMLParser*>(parent_parser);
	if(!MCMC_XMLParser_parent_parser) error("mpi_log_normal_sync_proposal_XMLParser: parent parser must be of type MCMC_XMLParser");
	_mcmc = MCMC_XMLParser_parent_parser->get_mcmc();
	// Don't instantiate the variable until the values have been read in
}

void mpi_log_normal_sync_proposal_XMLParser::implement_characters(const XMLCh* const chars, const XMLSize_t length) {
	string message = "";
	int i;
	for(i=0;i<length;i++) message += chars[i];
	istringstream oss(message);
	vector<string> target(0);
	string val_j;
	while(!(oss >> val_j).fail()) {
		target.push_back(val_j);
	}
	if(target.size()==0) error("mpi_log_normal_sync_proposal_XMLParser: no parameters entered");
	double double_sd;
	if(!from_string<double>(double_sd,sattr[0])) error("mpi_log_normal_sync_proposal_XMLParser: cannot convert parameter sd to double");
	double double_weight;
	if(!from_string<double>(double_weight,sattr[1])) error("mpi_log_normal_sync_proposal_XMLParser: cannot convert parameter weight to double");
	int int_handshake;
	if(!from_string<int>(int_handshake,sattr[2])) error("mpi_log_normal_sync_proposal_XMLParser: cannot convert parameter handshake to int");
#ifdef _MPI_WILL_BE_LINKED
	new MPILogNormalSyncProposal(_mcmc,target,double_weight,int_handshake,double_sd);
#else
	error("mpi_log_normal_sync_proposal_XMLParser: only available in MPI environment");
#endif
}

mpi_log_uniform_proposal_XMLParser::mpi_log_uniform_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<mpi_log_uniform_proposal_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 4;
	const char* attrNames[nattr] = {"parameter","half-width","weight","handshake"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	vector<string> target(1,sattr[0]);
	double double_half_width;
	if(!from_string<double>(double_half_width,sattr[1])) error("mpi_log_uniform_proposal_XMLParser: cannot convert parameter half-width to double");
	double double_weight;
	if(!from_string<double>(double_weight,sattr[2])) error("mpi_log_uniform_proposal_XMLParser: cannot convert parameter weight to double");
	int int_handshake;
	if(!from_string<int>(int_handshake,sattr[3])) error("mpi_log_uniform_proposal_XMLParser: cannot convert parameter handshake to int");
	// Get _mcmc from parent parser via dynamic type-checking
	MCMC_XMLParser* MCMC_XMLParser_parent_parser = dynamic_cast<MCMC_XMLParser*>(parent_parser);
	if(!MCMC_XMLParser_parent_parser) error("mpi_log_uniform_proposal_XMLParser: parent parser must be of type MCMC_XMLParser");
	_mcmc = MCMC_XMLParser_parent_parser->get_mcmc();
#ifdef _MPI_WILL_BE_LINKED
	new MPILogUniformProposal(_mcmc,target,double_weight,int_handshake,double_half_width);
#else
	error("mpi_log_uniform_proposal_XMLParser: only available in MPI environment");
#endif
}

mpi_logit_uniform_proposal_XMLParser::mpi_logit_uniform_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<mpi_logit_uniform_proposal_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 4;
	const char* attrNames[nattr] = {"parameter","half-width","weight","handshake"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	vector<string> target(1,sattr[0]);
	double double_half_width;
	if(!from_string<double>(double_half_width,sattr[1])) error("mpi_logit_uniform_proposal_XMLParser: cannot convert parameter half-width to double");
	double double_weight;
	if(!from_string<double>(double_weight,sattr[2])) error("mpi_logit_uniform_proposal_XMLParser: cannot convert parameter weight to double");
	int int_handshake;
	if(!from_string<int>(int_handshake,sattr[3])) error("mpi_logit_uniform_proposal_XMLParser: cannot convert parameter handshake to int");
	// Get _mcmc from parent parser via dynamic type-checking
	MCMC_XMLParser* MCMC_XMLParser_parent_parser = dynamic_cast<MCMC_XMLParser*>(parent_parser);
	if(!MCMC_XMLParser_parent_parser) error("mpi_logit_uniform_proposal_XMLParser: parent parser must be of type MCMC_XMLParser");
	_mcmc = MCMC_XMLParser_parent_parser->get_mcmc();
#ifdef _MPI_WILL_BE_LINKED
	new MPILogItUniformProposal(_mcmc,target,double_weight,int_handshake,double_half_width);
#else
	error("mpi_logit_uniform_proposal_XMLParser: only available in MPI environment");
#endif
}

mpi_switch_proposal_XMLParser::mpi_switch_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<mpi_switch_proposal_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 2;
	const char* attrNames[nattr] = {"weight","handshake"};
	sattr = attributesToStrings(nattr,attrNames,attrs);
	// Get _mcmc from parent parser via dynamic type-checking
	MCMC_XMLParser* MCMC_XMLParser_parent_parser = dynamic_cast<MCMC_XMLParser*>(parent_parser);
	if(!MCMC_XMLParser_parent_parser) error("mpi_switch_proposal_XMLParser: parent parser must be of type MCMC_XMLParser");
	_mcmc = MCMC_XMLParser_parent_parser->get_mcmc();
	// Don't instantiate the variable until the values have been read in
}

void mpi_switch_proposal_XMLParser::implement_characters(const XMLCh* const chars, const XMLSize_t length) {
	string message = "";
	int i;
	for(i=0;i<length;i++) message += chars[i];
	istringstream oss(message);
	vector<string> target(0);
	string val_j;
	while(!(oss >> val_j).fail()) {
		target.push_back(val_j);
	}
	if(target.size()==0) error("mpi_switch_proposal_XMLParser: no parameters entered");
	double double_weight;
	if(!from_string<double>(double_weight,sattr[0])) error("mpi_switch_proposal_XMLParser: cannot convert parameter weight to double");
	int int_handshake;
	if(!from_string<int>(int_handshake,sattr[1])) error("mpi_switch_proposal_XMLParser: cannot convert parameter handshake to int");
#ifdef _MPI_WILL_BE_LINKED
	new MPISwitchProposal(_mcmc,target,double_weight,int_handshake);
#else
	error("mpi_switch_proposal_XMLParser: only available in MPI environment");
#endif
}

mpi_uniform_proposal_XMLParser::mpi_uniform_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<mpi_uniform_proposal_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 4;
	const char* attrNames[nattr] = {"parameter","half-width","weight","handshake"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	vector<string> target(1,sattr[0]);
	double double_half_width;
	if(!from_string<double>(double_half_width,sattr[1])) error("mpi_uniform_proposal_XMLParser: cannot convert parameter half-width to double");
	double double_weight;
	if(!from_string<double>(double_weight,sattr[2])) error("mpi_uniform_proposal_XMLParser: cannot convert parameter weight to double");
	int int_handshake;
	if(!from_string<int>(int_handshake,sattr[3])) error("mpi_uniform_proposal_XMLParser: cannot convert parameter handshake to int");
	// Get _mcmc from parent parser via dynamic type-checking
	MCMC_XMLParser* MCMC_XMLParser_parent_parser = dynamic_cast<MCMC_XMLParser*>(parent_parser);
	if(!MCMC_XMLParser_parent_parser) error("mpi_uniform_proposal_XMLParser: parent parser must be of type MCMC_XMLParser");
	_mcmc = MCMC_XMLParser_parent_parser->get_mcmc();
#ifdef _MPI_WILL_BE_LINKED
	new MPIUniformProposal(_mcmc,target,double_weight,int_handshake,double_half_width);
#else
	error("mpi_uniform_proposal_XMLParser: only available in MPI environment");
#endif
}

uniform_proposal_XMLParser::uniform_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<uniform_proposal_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"parameter","half-width","weight"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	vector<string> target(1,sattr[0]);
	double double_half_width;
	if(!from_string<double>(double_half_width,sattr[1])) error("uniform_proposal_XMLParser: cannot convert parameter half-width to double");
	double double_weight;
	if(!from_string<double>(double_weight,sattr[2])) error("uniform_proposal_XMLParser: cannot convert parameter weight to double");
	// Get _mcmc from parent parser via dynamic type-checking
	MCMC_XMLParser* MCMC_XMLParser_parent_parser = dynamic_cast<MCMC_XMLParser*>(parent_parser);
	if(!MCMC_XMLParser_parent_parser) error("uniform_proposal_XMLParser: parent parser must be of type MCMC_XMLParser");
	_mcmc = MCMC_XMLParser_parent_parser->get_mcmc();
	new UniformProposal(_mcmc,target,double_weight,double_half_width);
}

MCMC_log_parameter_XMLParser::MCMC_log_parameter_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<MCMC_log_parameter_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 1;
	const char* attrNames[nattr] = {"idref"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// Get _log from parent parser via dynamic type-checking
	MCMC_log_XMLParser* MCMC_log_XMLParser_parent_parser = dynamic_cast<MCMC_log_XMLParser*>(parent_parser);
	if(!MCMC_log_XMLParser_parent_parser) error("MCMC_log_parameter_XMLParser: parent parser must be of type MCMC_log_XMLParser");
	_log = MCMC_log_XMLParser_parent_parser->get_log();
	_log->add_parameter(sattr[0]);
}

MCMC_log_loglikelihood_XMLParser::MCMC_log_loglikelihood_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<MCMC_log_loglikelihood_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 1;
	const char* attrNames[nattr] = {"idref"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// Get _log from parent parser via dynamic type-checking
	MCMC_log_XMLParser* MCMC_log_XMLParser_parent_parser = dynamic_cast<MCMC_log_XMLParser*>(parent_parser);
	if(!MCMC_log_XMLParser_parent_parser) error("MCMC_log_loglikelihood_XMLParser: parent parser must be of type MCMC_log_XMLParser");
	_log = MCMC_log_XMLParser_parent_parser->get_log();
	_log->add_loglik(sattr[0]);
}

MCMC_log_XMLParser::MCMC_log_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<MCMC_log_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 7;
	const char* attrNames[nattr] = {"file","burnin","thinning","record-iter","record-move","record-proposals","separator"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	int int_burnin;
	if(!from_string<int>(int_burnin,sattr[1])) error("MCMC_log_XMLParser: cannot convert parameter burnin to int");
	int int_thinning;
	if(!from_string<int>(int_thinning,sattr[2])) error("MCMC_log_XMLParser: cannot convert parameter thinning to int");
	int i;
	for(i=0;i<sattr[3].length();i++) sattr[3][i] = toupper(sattr[3][i]);
	if(sattr[3]=="TRUE") sattr[3] = "1";
	if(sattr[3]=="FALSE") sattr[3] = "0";
	bool bool_record_iter;
	if(!from_string<bool>(bool_record_iter,sattr[3])) error("MCMC_log_XMLParser: cannot convert parameter record-iter to bool");
	for(i=0;i<sattr[4].length();i++) sattr[4][i] = toupper(sattr[4][i]);
	if(sattr[4]=="TRUE") sattr[4] = "1";
	if(sattr[4]=="FALSE") sattr[4] = "0";
	bool bool_record_move;
	if(!from_string<bool>(bool_record_move,sattr[4])) error("MCMC_log_XMLParser: cannot convert parameter record-move to bool");
	for(i=0;i<sattr[5].length();i++) sattr[5][i] = toupper(sattr[5][i]);
	if(sattr[5]=="TRUE") sattr[5] = "1";
	if(sattr[5]=="FALSE") sattr[5] = "0";
	bool bool_record_proposals;
	if(!from_string<bool>(bool_record_proposals,sattr[5])) error("MCMC_log_XMLParser: cannot convert parameter record-proposals to bool");
	if(sattr[6]=="tab") sattr[6] = "\t";
	if(sattr[0]=="screen") {
		_log = new MCMC_log(getDAG(),&cout,int_burnin,int_thinning,bool_record_iter,bool_record_move,bool_record_proposals,sattr[6]);
	}
	else {
		_log = new MCMC_log(getDAG(),sattr[0],int_burnin,int_thinning,bool_record_iter,bool_record_move,bool_record_proposals,sattr[6]);
	}
}

void MCMC_log_XMLParser::implement_startElement(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs) {
	string element = elementName(localname);
	if(element=="parameter") {
		_child_parser = new MCMC_log_parameter_XMLParser(uri,localname,qname,attrs,_master_parser,this);
	}
	else if(element=="loglikelihood") {
		_child_parser = new MCMC_log_loglikelihood_XMLParser(uri,localname,qname,attrs,_master_parser,this);
	}
	else DAGXMLParserTemplate<MCMC_log_XMLParser>::implement_startElement(uri,localname,qname,attrs);
}

MCMC_XMLParser::MCMC_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<MCMC_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 5;
	const char* attrNames[nattr] = {"niter","seed","screen_update","random_sweep","performance_interval"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// seed might be and niter and screen_update must be specified as numeric, in which case they are instantiated as Variables
	int int_niter;
	if(!from_string<int>(int_niter,sattr[0])) error("MCMC_XMLParser: cannot convert parameter niter to int");
	int int_seed;
	if(!from_string<int>(int_seed,sattr[1])) {
		if(sattr[1]!="timer") error("MCMC_XMLParser: seed must have integer value or \"timer\"");
		int_seed = -(int)time(NULL);
		cout << "Seed set to timer: " << int_seed << endl;
	}
	double double_screen_update;
	if(!from_string<double>(double_screen_update,sattr[2])) error("MCMC_XMLParser: cannot convert parameter screen_update to double");
	int i;
	for(i=0;i<sattr[3].length();i++) sattr[3][i] = toupper(sattr[3][i]);
	if(sattr[3]=="TRUE") sattr[3] = "1";
	if(sattr[3]=="FALSE") sattr[3] = "0";
	bool bool_sweep;
	if(!from_string<bool>(bool_sweep,sattr[3])) error("MCMC_XMLParser: cannot convert parameter random_sweep to bool");
	int int_performance_interval;
	if(!from_string<int>(int_performance_interval,sattr[4]))  error("MCMC_XMLParser: cannot convert parameter performance_interval to int");
	_mcmc = new MCMC(getDAG(),int_seed,int_niter,double_screen_update,bool_sweep,int_performance_interval);
}

MCMC* MCMC_XMLParser::get_mcmc() {
	return _mcmc;
}

Powell_XMLParser::Powell_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<Powell_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 1;
	const char* attrNames[nattr] = {"screen_update"};
	sattr = attributesToStrings(nattr,attrNames,attrs);
	// Don't instantiate the variable until the values have been read in
}

void Powell_XMLParser::implement_characters(const XMLCh* const chars, const XMLSize_t length) {
	string message = "";
	int i;
	for(i=0;i<length;i++) message += chars[i];
	istringstream oss(message);
	vector<string> val(0);
	string val_j;
	while(!(oss >> val_j).fail()) {
		val.push_back(val_j);
	}
	if(val.size()==0) error("Powell_XMLParser: no targets entered");
	new PowellML(getDAG(),val);
}

void LoadInferenceXML() {
	topLevel_XMLParser::add_child("mcmc",&MCMC_XMLParser::factory);
	MCMC_XMLParser::add_child("continuous_mosaic_extend_block",&continuous_mosaic_extend_block_XMLParser::factory);
	MCMC_XMLParser::add_child("continuous_mosaic_log_uniform_proposal",&continuous_mosaic_log_uniform_proposal_XMLParser::factory);
	MCMC_XMLParser::add_child("continuous_mosaic_splitmerge_block",&continuous_mosaic_splitmerge_block_XMLParser::factory);
	MCMC_XMLParser::add_child("continuous_mosaic_uniform_proposal",&continuous_mosaic_uniform_proposal_XMLParser::factory);
	MCMC_XMLParser::add_child("continuous_vector_uniform_proposal",&continuous_vector_uniform_proposal_XMLParser::factory);
	MCMC_XMLParser::add_child("continuous_vector_log_uniform_proposal",&continuous_vector_log_uniform_proposal_XMLParser::factory);
	MCMC_XMLParser::add_child("log_uniform_proposal",&log_uniform_proposal_XMLParser::factory);
	MCMC_XMLParser::add_child("logit_uniform_proposal",&logit_uniform_proposal_XMLParser::factory);
	MCMC_XMLParser::add_child("mpi_adaptive_metropolis",&mpi_adaptive_metropolis_XMLParser::factory);
	MCMC_XMLParser::add_child("mpi_adaptive_metropolis_within_gibbs",&mpi_adaptive_metropolis_within_gibbs_XMLParser::factory);
	MCMC_XMLParser::add_child("mpi_log_normal_proposal",&mpi_log_normal_proposal_XMLParser::factory);
	MCMC_XMLParser::add_child("mpi_log_normal_sync_proposal",&mpi_log_normal_sync_proposal_XMLParser::factory);
	MCMC_XMLParser::add_child("mpi_log_uniform_proposal",&mpi_log_uniform_proposal_XMLParser::factory);
	MCMC_XMLParser::add_child("mpi_logit_uniform_proposal",&mpi_logit_uniform_proposal_XMLParser::factory);
	MCMC_XMLParser::add_child("mpi_switch_proposal",&mpi_switch_proposal_XMLParser::factory);
	MCMC_XMLParser::add_child("mpi_uniform_proposal",&mpi_uniform_proposal_XMLParser::factory);
	MCMC_XMLParser::add_child("uniform_proposal",&uniform_proposal_XMLParser::factory);
	MCMC_XMLParser::add_child("log",&MCMC_log_XMLParser::factory);

	topLevel_XMLParser::add_child("powell",&Powell_XMLParser::factory);
}
	
} // namespace gcat
