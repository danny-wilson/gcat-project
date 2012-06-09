/*  Copyright 2012 Daniel Wilson.
 *
 *  InferenceXML.h
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
#ifndef _INFERENCE_XMLPARSER_H_
#define _INFERENCE_XMLPARSER_H_
#include <DAG/DAGXMLParser.h>
#include <time.h>
#include <Inference/MCMC/Moves.h>
#include <Inference/MCMC/MPIMoves.h>
#include <Inference/MCMC/ContinuousMosaicMoves.h>
#include <iostream>
#include <Inference/ML/PowellML.h>

using std::cout;

namespace gcat {

/*	<xs:element name="continuous_mosaic_extend_block_proposal">
		<xs:complexType>
			<xs:attribute name="parameter" type="xs:string" use="required"/>
			<xs:attribute name="mean_extension" type="xs:decimal" default="1.2"/>
			<xs:attribute name="weight" type="xs:decimal" default="1"/>
		</xs:complexType>
	</xs:element>
 */
class continuous_mosaic_extend_block_XMLParser : public DAGXMLParserTemplate<continuous_mosaic_extend_block_XMLParser> {
protected:
	MCMC* _mcmc;
public:
	continuous_mosaic_extend_block_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="continuous_mosaic_log_uniform_proposal">
		<xs:complexType>
			<xs:attribute name="parameter" type="xs:string" use="required"/>
			<xs:attribute name="half-width" type="xs:decimal" default="1"/>
			<xs:attribute name="weight" type="xs:decimal" default="1"/>
		</xs:complexType>
	</xs:element>
 */
class continuous_mosaic_log_uniform_proposal_XMLParser : public DAGXMLParserTemplate<continuous_mosaic_log_uniform_proposal_XMLParser> {
protected:
	MCMC* _mcmc;
public:
	continuous_mosaic_log_uniform_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="continuous_mosaic_splitmerge_block">
		<xs:complexType>
			<xs:attribute name="parameter" type="xs:string" use="required"/>
			<xs:attribute name="p" type="xs:decimal" use="required"/>
			<xs:attribute name="weight" type="xs:decimal" default="1"/>
			<xs:attribute name="mean_type" type="xs:string" default="arithmetic"/>
		</xs:complexType>
	</xs:element>
 */
class continuous_mosaic_splitmerge_block_XMLParser : public DAGXMLParserTemplate<continuous_mosaic_splitmerge_block_XMLParser> {
protected:
	MCMC* _mcmc;
public:
	continuous_mosaic_splitmerge_block_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="continuous_mosaic_uniform_proposal">
		<xs:complexType>
			<xs:attribute name="parameter" type="xs:string" use="required"/>
			<xs:attribute name="half-width" type="xs:decimal" default="1"/>
			<xs:attribute name="weight" type="xs:decimal" default="1"/>
		</xs:complexType>
	</xs:element>
 */
class continuous_mosaic_uniform_proposal_XMLParser : public DAGXMLParserTemplate<continuous_mosaic_uniform_proposal_XMLParser> {
protected:
	MCMC* _mcmc;
public:
	continuous_mosaic_uniform_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="log_uniform_proposal">
		<xs:complexType>
			<xs:attribute name="parameter" type="xs:string" use="required"/>
			<xs:attribute name="half-width" type="xs:decimal" default="1"/>
			<xs:attribute name="weight" type="xs:decimal" default="1"/>
		</xs:complexType>
	</xs:element> 
 */
class log_uniform_proposal_XMLParser : public DAGXMLParserTemplate<log_uniform_proposal_XMLParser> {
protected:
	MCMC* _mcmc;
public:
	log_uniform_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="logit_uniform_proposal">
		<xs:complexType>
			<xs:attribute name="parameter" type="xs:string" use="required"/>
			<xs:attribute name="half-width" type="xs:decimal" default="1"/>
			<xs:attribute name="weight" type="xs:decimal" default="1"/>
		</xs:complexType>
	</xs:element> 
 */
class logit_uniform_proposal_XMLParser : public DAGXMLParserTemplate<logit_uniform_proposal_XMLParser> {
protected:
	MCMC* _mcmc;
public:
	logit_uniform_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="mpi_adaptive_metropolis">
		<xs:complexType>
			<xs:sequence>
				<xs:element name="parameters" type="xs:string"/>
				<xs:element name="C0" type="xs:decimal"/>
			</xs:sequence>
			<xs:attribute name="weight" type="xs:decimal" default="1"/>
			<xs:attribute name="handshake" type="xs:integer" use="required"/>
			<xs:attribute name="epsilon" type="xs:decimal" use="required"/>
			<xs:attribute name="t0" type="xs:decimal" use="required"/>
			<xs:attribute name="denom" type="xs:decimal" use="required"/>
		</xs:complexType>
	</xs:element>
 */
class mpi_adaptive_metropolis_parameters_XMLParser : public DAGXMLParserTemplate<mpi_adaptive_metropolis_parameters_XMLParser> {
protected:
	MCMC* _mcmc;
public:
	mpi_adaptive_metropolis_parameters_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
	void implement_characters(const XMLCh* const chars, const XMLSize_t length);
};

class mpi_adaptive_metropolis_C0_XMLParser : public DAGXMLParserTemplate<mpi_adaptive_metropolis_C0_XMLParser> {
protected:
	MCMC* _mcmc;
public:
	mpi_adaptive_metropolis_C0_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
	void implement_characters(const XMLCh* const chars, const XMLSize_t length);
};

class mpi_adaptive_metropolis_XMLParser : public DAGXMLParserTemplate<mpi_adaptive_metropolis_XMLParser> {
protected:
	MCMC* _mcmc;
	// Allow child parsers access to member variables
	friend class mpi_adaptive_metropolis_parameters_XMLParser;
	friend class mpi_adaptive_metropolis_C0_XMLParser;
	double double_weight, double_epsilon, double_t0, double_denom;
	int int_handshake;
	vector<string> target;
	Matrix<double> C0;
public:
	mpi_adaptive_metropolis_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
	void implement_startElement(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs);
	void implement_endElement(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname);
	MCMC* get_mcmc() { return _mcmc; };
};

/*	<xs:element name="mpi_adaptive_metropolis_within_gibbs">
		<xs:complexType>
			<xs:attribute name="parameter" type="xs:string" use="required"/>
			<xs:attribute name="delta" type="xs:decimal" default="0.01"/>
			<xs:attribute name="batchsize" type="xs:decimal" default="50"/>
			<xs:attribute name="sd" type="xs:decimal" default="1"/>
			<xs:attribute name="weight" type="xs:decimal" default="1"/>
			<xs:attribute name="handshake" type="xs:integer" use="required"/>
		</xs:complexType>
	</xs:element>
 */
class mpi_adaptive_metropolis_within_gibbs_XMLParser : public DAGXMLParserTemplate<mpi_adaptive_metropolis_within_gibbs_XMLParser> {
protected:
	MCMC* _mcmc;
public:
	mpi_adaptive_metropolis_within_gibbs_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="mpi_log_normal_proposal">
		<xs:complexType>
			<xs:attribute name="parameter" type="xs:string" use="required"/>
			<xs:attribute name="sd" type="xs:decimal" default="1"/>
			<xs:attribute name="weight" type="xs:decimal" default="1"/>
			<xs:attribute name="handshake" type="xs:integer" use="required"/>
		</xs:complexType>
	</xs:element>
 */
class mpi_log_normal_proposal_XMLParser : public DAGXMLParserTemplate<mpi_log_normal_proposal_XMLParser> {
protected:
	MCMC* _mcmc;
public:
	mpi_log_normal_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="mpi_log_normal_sync_proposal">
		<xs:complexType>
			<xs:simpleContent>
				<xs:extension base="string_list">
					<xs:attribute name="sd" type="xs:decimal" default="1"/>
					<xs:attribute name="weight" type="xs:decimal" default="1"/>
					<xs:attribute name="handshake" type="xs:integer" use="required"/>
				</xs:extension>
			</xs:simpleContent>
		</xs:complexType>
	</xs:element>
 */
class mpi_log_normal_sync_proposal_XMLParser : public DAGXMLParserTemplate<mpi_log_normal_sync_proposal_XMLParser> {
protected:
	vector<string> sattr;
	MCMC* _mcmc;
public:
	mpi_log_normal_sync_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
	void implement_characters(const XMLCh* const chars, const XMLSize_t length);
};

/*	<xs:element name="mpi_log_uniform_proposal">
		<xs:complexType>
			<xs:attribute name="parameter" type="xs:string" use="required"/>
			<xs:attribute name="half-width" type="xs:decimal" default="1"/>
			<xs:attribute name="weight" type="xs:decimal" default="1"/>
			<xs:attribute name="handshake" type="xs:integer" use="required"/>
		</xs:complexType>
	</xs:element>
 */
class mpi_log_uniform_proposal_XMLParser : public DAGXMLParserTemplate<mpi_log_uniform_proposal_XMLParser> {
protected:
	MCMC* _mcmc;
public:
	mpi_log_uniform_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="mpi_logit_uniform_proposal">
		<xs:complexType>
			<xs:attribute name="parameter" type="xs:string" use="required"/>
			<xs:attribute name="half-width" type="xs:decimal" default="1"/>
			<xs:attribute name="weight" type="xs:decimal" default="1"/>
			<xs:attribute name="handshake" type="xs:integer" use="required"/>
		</xs:complexType>
	</xs:element>
 */
class mpi_logit_uniform_proposal_XMLParser : public DAGXMLParserTemplate<mpi_logit_uniform_proposal_XMLParser> {
protected:
	MCMC* _mcmc;
public:
	mpi_logit_uniform_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="mpi_switch_proposal">
		<xs:complexType>
			<xs:simpleContent>
				<xs:extension base="string_list">
					<xs:attribute name="weight" type="xs:decimal" default="1"/>
					<xs:attribute name="handshake" type="xs:integer" use="required"/>
				</xs:extension>
			</xs:simpleContent>
		</xs:complexType>
	</xs:element>
 */
class mpi_switch_proposal_XMLParser : public DAGXMLParserTemplate<mpi_switch_proposal_XMLParser> {
protected:
	vector<string> sattr;
	MCMC* _mcmc;
public:
	mpi_switch_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
	void implement_characters(const XMLCh* const chars, const XMLSize_t length);
};

/*	<xs:element name="mpi_uniform_proposal">
		<xs:complexType>
			<xs:attribute name="parameter" type="xs:string" use="required"/>
			<xs:attribute name="half-width" type="xs:decimal" default="1"/>
			<xs:attribute name="weight" type="xs:decimal" default="1"/>
			<xs:attribute name="handshake" type="xs:integer" use="required"/>
		</xs:complexType>
	</xs:element>
 */
class mpi_uniform_proposal_XMLParser : public DAGXMLParserTemplate<mpi_uniform_proposal_XMLParser> {
protected:
	MCMC* _mcmc;
public:
	mpi_uniform_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="uniform_proposal">
		<xs:complexType>
			<xs:attribute name="parameter" type="xs:string" use="required"/>
			<xs:attribute name="half-width" type="xs:decimal" default="1"/>
			<xs:attribute name="weight" type="xs:decimal" default="1"/>
		</xs:complexType>
	</xs:element> 
 */
class uniform_proposal_XMLParser : public DAGXMLParserTemplate<uniform_proposal_XMLParser> {
protected:
	MCMC* _mcmc;
public:
	uniform_proposal_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="parameter">
		<xs:complexType>
			<xs:attribute name="name" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
*/
class MCMC_log_parameter_XMLParser : public DAGXMLParserTemplate<MCMC_log_parameter_XMLParser> {
protected:
	MCMC_log* _log;
public:
	MCMC_log_parameter_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="loglikelihood">
		<xs:complexType>
			<xs:attribute name="idref" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element> 
 */
class MCMC_log_loglikelihood_XMLParser : public DAGXMLParserTemplate<MCMC_log_loglikelihood_XMLParser> {
	MCMC_log* _log;
public:
	MCMC_log_loglikelihood_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:complexType name="log_elements">
		<xs:choice minOccurs="0" maxOccurs="unbounded">
			<xs:element ref="parameter"/>
			<xs:element ref="loglikelihood"/>
		</xs:choice>
	</xs:complexType>
 
	<xs:element name="log">
		<xs:complexType>
			<xs:complexContent>
				<xs:extension base="log_elements">
					<xs:attribute name="file" type="xs:string" use="required"/>
					<xs:attribute name="burnin" type="xs:integer" default="0"/>
					<xs:attribute name="thinning" type="xs:integer" use="required"/>
					<xs:attribute name="record-iter" type="xs:boolean" default="true"/>
					<xs:attribute name="record-move" type="xs:boolean" default="false"/>
					<xs:attribute name="record-proposals" type="xs:boolean" default="false"/>
					<xs:attribute name="separator" type="xs:string" default="tab"/>
				</xs:extension>
			</xs:complexContent>
		</xs:complexType>
	</xs:element>
 */
class MCMC_log_XMLParser : public DAGXMLParserTemplate<MCMC_log_XMLParser> {
protected:
	MCMC_log* _log;
public:
	MCMC_log_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
	void implement_startElement(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs);
	MCMC_log* get_log() { return _log; };
};

/*	<xs:complexType name="mcmc_elements">
		<xs:choice minOccurs="0" maxOccurs="unbounded">
			<xs:element ref="uniform_proposal"/>		
			<xs:element ref="log" minOccurs="1"/>
		</xs:choice>
	</xs:complexType>
 
	<xs:element name="mcmc">
		<xs:complexType>
			<xs:complexContent>
				<xs:extension base="mcmc_elements">
				<xs:attribute name="niter" type="xs:positiveInteger" use="required"/>
				<xs:attribute name="seed" type="xs:string" default="timer"/>
				<xs:attribute name="screen_update" type="xs:double" default="0"/>
				<xs:attribute name="random_sweep" type="xs:string" default="true"/>
				<xs:attribute name="performance_interval" type="xs:nonNegativeInteger" default="0"/>
			</xs:extension>
		</xs:complexContent>
	</xs:complexType>
 </xs:element>
 */
class MCMC_XMLParser : public DAGXMLParserTemplate<MCMC_XMLParser> {
protected:
	MCMC* _mcmc;
public:
	MCMC_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
	MCMC* get_mcmc();
};

/*	<xs:complexType name="powell_type">
		<xs:simpleContent>
			<xs:extension base="string_list">
				<xs:attribute name="screen_update" type="xs:double" default="0"/>
			</xs:extension>
		</xs:simpleContent>
	</xs:complexType>
	<xs:element name="powell" type="powell_type"/>
 */
class Powell_XMLParser : public DAGXMLParserTemplate<Powell_XMLParser> {
	vector<string> sattr;
public:
	Powell_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
	void implement_characters(const XMLCh* const chars, const XMLSize_t length);
};

void LoadInferenceXML();
	
} // namespace gcat

#endif// _INFERENCE_XMLPARSER_H_

