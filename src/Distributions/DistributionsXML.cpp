/*  Copyright 2012 Daniel Wilson.
 *
 *  DistributionsXML.cpp
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
#include <Distributions/DistributionsXML.h>
#include <Distributions/Binomial.h>
#include <Distributions/Beta.h>
#include <Distributions/ContinuousMosaic.h>
#include <Distributions/ContinuousMosaicBetaMixture.h>
#include <Distributions/ContinuousMosaicMixture.h>
#include <Distributions/ContinuousMixture.h>
#include <Distributions/Gamma.h>
#include <Distributions/ImproperBeta.h>
#include <Distributions/ImproperLogUniform.h>
#include <Distributions/ImproperUniform.h>
#include <Distributions/InverseGamma.h>
#include <Distributions/LogCauchy.h>
#include <Distributions/LogNormal.h>
#include <Distributions/LogUniform.h>
#include <Distributions/Normal.h>
#include <Distributions/Uniform.h>
#include <RandomVariables/ContinuousVector.h>
#include <Distributions/ContinuousVector.h>

namespace gcat {

binomial_distribution_XMLParser::binomial_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<binomial_distribution_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"id","N","p"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// N and p can be specified as numeric, in which case they must be instantiated as Variables
	int int_N;
	if(from_string<int>(int_N,sattr[1])) {
		// Internally-generated name
		sattr[1] = "_" + sattr[0] + ".N";
		new DiscreteRV(sattr[1],getDAG(),int_N);
		getDAG()->set_constant(sattr[1]);
	}
	double double_p;
	if(from_string<double>(double_p,sattr[2])) {
		// Internally-generated name
		sattr[2] = "_" + sattr[0] + ".p";
		new ContinuousRV(sattr[2],getDAG(),double_p);
		getDAG()->set_constant(sattr[2]);
	}
	new BinomialDistribution(sattr[0],getDAG());
	getDAG()->assign_parameter_to_distribution(sattr[0],"N",sattr[1]);
	getDAG()->assign_parameter_to_distribution(sattr[0],"p",sattr[2]);
}

beta_distribution_XMLParser::beta_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<beta_distribution_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"id","a","b"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// a and b can be specified as numeric, in which case they must be instantiated as Variables
	double double_a;
	if(from_string<double>(double_a,sattr[1])) {
		// Internally-generated name
		sattr[1] = "_" + sattr[0] + "." + attrNames[1];
		new ContinuousRV(sattr[1],getDAG(),double_a);
		getDAG()->set_constant(sattr[1]);
	}
	double double_b;
	if(from_string<double>(double_b,sattr[2])) {
		// Internally-generated name
		sattr[2] = "_" + sattr[0] + "." + attrNames[2];
		new ContinuousRV(sattr[2],getDAG(),double_b);
		getDAG()->set_constant(sattr[2]);
	}
	new BetaDistribution(sattr[0],getDAG());
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[1],sattr[1]);
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[2],sattr[2]);
}

continuous_mosaic_distribution_XMLParser::continuous_mosaic_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<continuous_mosaic_distribution_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"id","p","marginal"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	double double_p;
	if(from_string<double>(double_p,sattr[1])) {
		// Internally-generated name
		sattr[1] = "_" + sattr[0] + "." + attrNames[1];
		new ContinuousRV(sattr[1],getDAG(),double_p);
		getDAG()->set_constant(sattr[1]);
	}
	new ContinuousMosaicDistribution(sattr[0],getDAG());
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[1],sattr[1]);
	getDAG()->assign_distribution_to_compound_distribution(sattr[0],attrNames[2],sattr[2]);
}

continuous_mosaic_beta_mixture_distribution_XMLParser::continuous_mosaic_beta_mixture_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<continuous_mosaic_beta_mixture_distribution_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 4;
	const char* attrNames[nattr] = {"id","a","b","marginal"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	double double_a;
	if(from_string<double>(double_a,sattr[1])) {
		// Internally-generated name
		sattr[1] = "_" + sattr[0] + "." + attrNames[1];
		new ContinuousRV(sattr[1],getDAG(),double_a);
		getDAG()->set_constant(sattr[1]);
	}
	double double_b;
	if(from_string<double>(double_b,sattr[2])) {
		// Internally-generated name
		sattr[2] = "_" + sattr[0] + "." + attrNames[2];
		new ContinuousRV(sattr[2],getDAG(),double_b);
		getDAG()->set_constant(sattr[2]);
	}
	new ContinuousMosaicBetaMixtureDistribution(sattr[0],getDAG());
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[1],sattr[1]);
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[2],sattr[2]);
	getDAG()->assign_distribution_to_compound_distribution(sattr[0],attrNames[3],sattr[3]);
}

continuous_mosaic_mixture_distribution_XMLParser::continuous_mosaic_mixture_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<continuous_mosaic_mixture_distribution_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 4;
	const char* attrNames[nattr] = {"id","p","m","marginal"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// Vector of geometric probability parameters: do not allow variable name to be passed
	vector<double> vdouble_p;
	if(!string_to_vector<double>(vdouble_p,sattr[1])) error("continuous_mosaic_mixture_distribution_XMLParser: could not convert p to vector double");
	// Internally-generated name
	sattr[1] = "_" + sattr[0] + "." + attrNames[1];
	const int p_length = vdouble_p.size();
	new ContinuousVectorRV(p_length,sattr[1],getDAG(),vdouble_p);
	getDAG()->set_constant(sattr[1]);
	// Vector of mixture proportions: do not allow variable name to be passed
	vector<double> vdouble_m;
	if(!string_to_vector<double>(vdouble_m,sattr[2])) error("continuous_mosaic_mixture_distribution_XMLParser: could not convert m to vector double");
	// Internally-generated name
	sattr[2] = "_" + sattr[0] + "." + attrNames[2];
	if(vdouble_m.size()!=p_length) error("continuous_mosaic_mixture_distribution_XMLParser: vectors p and m must have same lengths");
	new ContinuousVectorRV(p_length,sattr[2],getDAG(),vdouble_m);
	getDAG()->set_constant(sattr[2]);
	new ContinuousMosaicMixtureDistribution(sattr[0],getDAG());
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[1],sattr[1]);
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[2],sattr[2]);
	getDAG()->assign_distribution_to_compound_distribution(sattr[0],attrNames[3],sattr[3]);
}
	
continuous_mixture_XMLParser::continuous_mixture_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<continuous_mixture_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 4;
	const char* attrNames[nattr] = {"id","p","distribution0","distribution1"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// a and b can be specified as numeric, in which case they must be instantiated as Variables
	double double_p;
	if(from_string<double>(double_p,sattr[1])) {
		// Internally-generated name
		sattr[1] = "_" + sattr[0] + "." + attrNames[1];
		new ContinuousRV(sattr[1],getDAG(),double_p);
		getDAG()->set_constant(sattr[1]);
	}
	new ContinuousMixture(sattr[0],getDAG());
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[1],sattr[1]);
	getDAG()->assign_distribution_to_compound_distribution(sattr[0],attrNames[2],sattr[2]);
	getDAG()->assign_distribution_to_compound_distribution(sattr[0],attrNames[3],sattr[3]);
}

	continuous_vector_distribution_XMLParser::continuous_vector_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<continuous_vector_distribution_XMLParser>(master_parser,parent_parser) {
		// Read in the attributes
		const int nattr = 2;
		const char* attrNames[nattr] = {"id","marginal"};
		vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
		new ContinuousVectorDistribution(sattr[0],getDAG());
		getDAG()->assign_distribution_to_compound_distribution(sattr[0],attrNames[1],sattr[1]);
	}
	
gamma_distribution_XMLParser::gamma_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<gamma_distribution_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"id","shape","scale"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// a and b can be specified as numeric, in which case they must be instantiated as Variables
	double double_a;
	if(from_string<double>(double_a,sattr[1])) {
		// Internally-generated name
		sattr[1] = "_" + sattr[0] + "." + attrNames[1];
		new ContinuousRV(sattr[1],getDAG(),double_a);
		getDAG()->set_constant(sattr[1]);
	}
	double double_b;
	if(from_string<double>(double_b,sattr[2])) {
		// Internally-generated name
		sattr[2] = "_" + sattr[0] + "." + attrNames[2];
		new ContinuousRV(sattr[2],getDAG(),double_b);
		getDAG()->set_constant(sattr[2]);
	}
	new GammaDistribution(sattr[0],getDAG());
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[1],sattr[1]);
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[2],sattr[2]);
}

improper_beta_distribution_XMLParser::improper_beta_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<improper_beta_distribution_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"id","a","b"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// a and b must be specified as numeric, so they are instantiated as Variables
	double double_a;
	if(!from_string<double>(double_a,sattr[1])) error("improper_beta_distribution_XMLParser: cannot convert parameter a to double");
	double double_b;
	if(!from_string<double>(double_b,sattr[2])) error("improper_beta_distribution_XMLParser: cannot convert parameter b to double");
	new ImproperBetaDistribution(sattr[0],getDAG(),double_a,double_b);
}

improper_log_uniform_distribution_XMLParser::improper_log_uniform_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<improper_log_uniform_distribution_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 1;
	const char* attrNames[nattr] = {"id"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	new ImproperLogUniformDistribution(sattr[0],getDAG());
}

improper_uniform_distribution_XMLParser::improper_uniform_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<improper_uniform_distribution_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 1;
	const char* attrNames[nattr] = {"id"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	new ImproperUniformDistribution(sattr[0],getDAG());
}

inverse_gamma_distribution_XMLParser::inverse_gamma_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<inverse_gamma_distribution_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"id","shape","scale"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// a and b can be specified as numeric, in which case they must be instantiated as Variables
	double double_a;
	if(from_string<double>(double_a,sattr[1])) {
		// Internally-generated name
		sattr[1] = "_" + sattr[0] + "." + attrNames[1];
		new ContinuousRV(sattr[1],getDAG(),double_a);
		getDAG()->set_constant(sattr[1]);
	}
	double double_b;
	if(from_string<double>(double_b,sattr[2])) {
		// Internally-generated name
		sattr[2] = "_" + sattr[0] + "." + attrNames[2];
		new ContinuousRV(sattr[2],getDAG(),double_b);
		getDAG()->set_constant(sattr[2]);
	}
	new InverseGammaDistribution(sattr[0],getDAG());
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[1],sattr[1]);
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[2],sattr[2]);
}

log_cauchy_distribution_XMLParser::log_cauchy_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<log_cauchy_distribution_XMLParser>(master_parser,parent_parser) {
  // Read in the attributes
  const int nattr = 3;
  const char* attrNames[nattr] = {"id","location","scale"};
  vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
  // a and b can be specified as numeric, in which case they must be instantiated as Variables
  double double_location;
  if(from_string<double>(double_location,sattr[1])) {
    // Internally-generated name
    sattr[1] = "_" + sattr[0] + "." + attrNames[1];
    new ContinuousRV(sattr[1],getDAG(),double_location);
    getDAG()->set_constant(sattr[1]);
  }
  double double_scale;
  if(from_string<double>(double_scale,sattr[2])) {
    // Internally-generated name
    sattr[2] = "_" + sattr[0] + "." + attrNames[2];
    new ContinuousRV(sattr[2],getDAG(),double_scale);
    getDAG()->set_constant(sattr[2]);
  }
  new LogCauchyDistribution(sattr[0],getDAG());
  getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[1],sattr[1]);
  getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[2],sattr[2]);
}

log_normal_distribution_XMLParser::log_normal_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<log_normal_distribution_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"id","mean","sd"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// a and b can be specified as numeric, in which case they must be instantiated as Variables
	double double_mean;
	if(from_string<double>(double_mean,sattr[1])) {
		// Internally-generated name
		sattr[1] = "_" + sattr[0] + "." + attrNames[1];
		new ContinuousRV(sattr[1],getDAG(),double_mean);
		getDAG()->set_constant(sattr[1]);
	}
	double double_sd;
	if(from_string<double>(double_sd,sattr[2])) {
		// Internally-generated name
		sattr[2] = "_" + sattr[0] + "." + attrNames[2];
		new ContinuousRV(sattr[2],getDAG(),double_sd);
		getDAG()->set_constant(sattr[2]);
	}
	new LogNormalDistribution(sattr[0],getDAG());
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[1],sattr[1]);
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[2],sattr[2]);
}

log_uniform_distribution_XMLParser::log_uniform_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<log_uniform_distribution_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"id","min","max"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// a and b can be specified as numeric, in which case they must be instantiated as Variables
	double double_min;
	if(from_string<double>(double_min,sattr[1])) {
		// Internally-generated name
		sattr[1] = "_" + sattr[0] + "." + attrNames[1];
		new ContinuousRV(sattr[1],getDAG(),double_min);
		getDAG()->set_constant(sattr[1]);
	}
	double double_max;
	if(from_string<double>(double_max,sattr[2])) {
		// Internally-generated name
		sattr[2] = "_" + sattr[0] + "." + attrNames[2];
		new ContinuousRV(sattr[2],getDAG(),double_max);
		getDAG()->set_constant(sattr[2]);
	}
	new LogUniformDistribution(sattr[0],getDAG());
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[1],sattr[1]);
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[2],sattr[2]);
}

normal_distribution_XMLParser::normal_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<normal_distribution_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"id","mean","sd"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// a and b can be specified as numeric, in which case they must be instantiated as Variables
	double double_mean;
	if(from_string<double>(double_mean,sattr[1])) {
		// Internally-generated name
		sattr[1] = "_" + sattr[0] + "." + attrNames[1];
		new ContinuousRV(sattr[1],getDAG(),double_mean);
		getDAG()->set_constant(sattr[1]);
	}
	double double_sd;
	if(from_string<double>(double_sd,sattr[2])) {
		// Internally-generated name
		sattr[2] = "_" + sattr[0] + "." + attrNames[2];
		new ContinuousRV(sattr[2],getDAG(),double_sd);
		getDAG()->set_constant(sattr[2]);
	}
	new NormalDistribution(sattr[0],getDAG());
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[1],sattr[1]);
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[2],sattr[2]);
}

uniform_distribution_XMLParser::uniform_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<uniform_distribution_XMLParser>(master_parser,parent_parser) {
	// Read in the attributes
	const int nattr = 3;
	const char* attrNames[nattr] = {"id","min","max"};
	vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
	// a and b can be specified as numeric, in which case they must be instantiated as Variables
	double double_min;
	if(from_string<double>(double_min,sattr[1])) {
		// Internally-generated name
		sattr[1] = "_" + sattr[0] + "." + attrNames[1];
		new ContinuousRV(sattr[1],getDAG(),double_min);
		getDAG()->set_constant(sattr[1]);
	}
	double double_max;
	if(from_string<double>(double_max,sattr[2])) {
		// Internally-generated name
		sattr[2] = "_" + sattr[0] + "." + attrNames[2];
		new ContinuousRV(sattr[2],getDAG(),double_max);
		getDAG()->set_constant(sattr[2]);
	}
	new UniformDistribution(sattr[0],getDAG());
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[1],sattr[1]);
	getDAG()->assign_parameter_to_distribution(sattr[0],attrNames[2],sattr[2]);
}

void LoadDistributionsXML() {
	topLevel_XMLParser::add_child("distributions",&distributions_XMLParser::factory);
	distributions_XMLParser::add_child("binomial_distribution",&binomial_distribution_XMLParser::factory);
	distributions_XMLParser::add_child("beta_distribution",&beta_distribution_XMLParser::factory);
	distributions_XMLParser::add_child("continuous_mosaic_distribution",&continuous_mosaic_distribution_XMLParser::factory);
	distributions_XMLParser::add_child("continuous_mosaic_beta_mixture_distribution",&continuous_mosaic_beta_mixture_distribution_XMLParser::factory);
	distributions_XMLParser::add_child("continuous_mosaic_mixture_distribution",&continuous_mosaic_mixture_distribution_XMLParser::factory);
	distributions_XMLParser::add_child("continuous_mixture",&continuous_mixture_XMLParser::factory);
	distributions_XMLParser::add_child("continuous_vector_distribution",&continuous_vector_distribution_XMLParser::factory);
	distributions_XMLParser::add_child("gamma_distribution",&gamma_distribution_XMLParser::factory);
	distributions_XMLParser::add_child("improper_beta_distribution",&improper_beta_distribution_XMLParser::factory);
	distributions_XMLParser::add_child("improper_log_uniform_distribution",&improper_log_uniform_distribution_XMLParser::factory);
	distributions_XMLParser::add_child("improper_uniform_distribution",&improper_uniform_distribution_XMLParser::factory);
	distributions_XMLParser::add_child("inverse_gamma_distribution",&inverse_gamma_distribution_XMLParser::factory);
  distributions_XMLParser::add_child("log_cauchy_distribution",&log_cauchy_distribution_XMLParser::factory);
	distributions_XMLParser::add_child("log_normal_distribution",&log_normal_distribution_XMLParser::factory);
	distributions_XMLParser::add_child("log_uniform_distribution",&log_uniform_distribution_XMLParser::factory);
	distributions_XMLParser::add_child("normal_distribution",&normal_distribution_XMLParser::factory);
	distributions_XMLParser::add_child("uniform_distribution",&uniform_distribution_XMLParser::factory);
}
	
} // namespace gcat
