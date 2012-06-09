/*  Copyright 2012 Daniel Wilson.
 *
 *  gammaMapXML.h
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
#ifndef _OMEGAMAP_XML_H_
#define _OMEGAMAP_XML_H_
#include <DAG/DAGXMLParser.h>
#include <Inference/MCMC/MCMC.h>

using namespace gcat;

namespace gcat_gammaMap {
	
// DISTRIBUTIONS

/*	<xs:element name="codon61_sequence_stationary_distribution">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="pi" type="xs:string" use="required"/>
	</xs:element>
 */
class codon61_sequence_stationary_distribution_XMLParser : public DAGXMLParserTemplate<codon61_sequence_stationary_distribution_XMLParser> {
public:
	codon61_sequence_stationary_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="gammaMapHMMHybrid">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="anc" type="xs:string" use="required"/>
			<xs:attribute name="theta" type="xs:string" use="required"/>
			<xs:attribute name="kappa" type="xs:string" use="required"/>
			<xs:attribute name="gamma1" type="xs:string" use="required"/>
			<xs:attribute name="gamma2" type="xs:string" use="required"/>
			<xs:attribute name="T" type="xs:string" use="required"/>
			<xs:attribute name="p" type="xs:string" use="required"/>
			<xs:attribute name="pi" type="xs:string" use="required"/>
			<xs:attribute name="gamma1_wt" type="xs:string" default="1"/>
			<xs:attribute name="gamma2_wt" type="xs:string" default="1"/>
		</xs:complexType>
	</xs:element>
 */
class gammaMapHMMHybrid_XMLParser : public DAGXMLParserTemplate<gammaMapHMMHybrid_XMLParser> {
public:
	gammaMapHMMHybrid_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

// RANDOM VARIABLES

/*	<xs:element name="codon_count">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="distribution" type="xs:string" default=""/>
			<xs:attribute name="file" type="xs:string" use="required"/>
			<xs:attribute name="format" type="xs:string" default="fasta"/>
			<xs:attribute name="encoding" type="xs:string" default="codon61"/>
		</xs:complexType>
	</xs:element>
 */
class codon_count_XMLParser : public DAGXMLParserTemplate<codon_count_XMLParser> {
public:
	codon_count_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:simpleType name="string_list">
		<xs:list itemType="xs:string"/>
	</xs:simpleType>

	<xs:element name="codon_sequence">
		<xs:complexType>
			<xs:simpleContent>
				<xs:extension base="string_list">
					<xs:attribute name="id" type="xs:string" use="required"/>
					<xs:attribute name="distribution" type="xs:string" default=""/>
					<xs:attribute name="encoding" type="xs:string" default="codon61"/>
				</xs:extension>
			</xs:simpleContent>
		</xs:complexType>
	</xs:element>
 */
class codon_sequence_XMLParser : public DAGXMLParserTemplate<codon_sequence_XMLParser> {
	vector<string> sattr;
public:
	codon_sequence_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
	void implement_characters(const XMLCh* const chars, const XMLSize_t length);
};

// TRANSFORMATIONS

/*	<xs:element name="gammaMapHMMHybrid_path_sampler">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="distribution" type="xs:string" use="required"/>
			<xs:attribute name="rv" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
 */
class gammaMapHMMHybrid_path_sampler_XMLParser : public DAGXMLParserTemplate<gammaMapHMMHybrid_path_sampler_XMLParser> {
public:
	gammaMapHMMHybrid_path_sampler_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

// INFERENCE

/*	<xs:element name="codon61_sequence_gibbs_sampler">
		<xs:complexType>
			<xs:attribute name="parameter" type="xs:string" use="required"/>
			<xs:attribute name="weight" type="xs:decimal" default="1"/>
		</xs:complexType>
	</xs:element>
 */
class codon61_sequence_gibbs_sampler_XMLParser : public DAGXMLParserTemplate<codon61_sequence_gibbs_sampler_XMLParser> {
protected:
	MCMC* _mcmc;
public:
	codon61_sequence_gibbs_sampler_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

// Load the library
xsd_string load_gammaMap_library();
	
} // namespace gcat_gammaMap

#endif//_OMEGAMAP_XML_H_
