/*  Copyright 2012 Daniel Wilson.
 *
 *  DistributionsXML.h
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
#ifndef _DISTRIBUTIONS_XML_H_
#define _DISTRIBUTIONS_XML_H_
#include <DAG/DAGXMLParser.h>

namespace gcat {

/*	<xs:element name="binomial_distribution">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="N" type="xs:string" use="required"/>
			<xs:attribute name="p" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
 */
class binomial_distribution_XMLParser : public DAGXMLParserTemplate<binomial_distribution_XMLParser> {
public:
	binomial_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="beta_distribution">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="a" type="xs:string" use="required"/>
			<xs:attribute name="b" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
 */
class beta_distribution_XMLParser : public DAGXMLParserTemplate<beta_distribution_XMLParser> {
public:
	beta_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="continuous_mosaic_distribution">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="p" type="xs:string" use="required"/>
			<xs:attribute name="marginal" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
 */
class continuous_mosaic_distribution_XMLParser : public DAGXMLParserTemplate<continuous_mosaic_distribution_XMLParser> {
public:
	continuous_mosaic_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="continuous_mosaic_beta_mixture_distribution">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="a" type="xs:string" use="required"/>
			<xs:attribute name="b" type="xs:string" use="required"/>
			<xs:attribute name="marginal" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element> 
 */
class continuous_mosaic_beta_mixture_distribution_XMLParser : public DAGXMLParserTemplate<continuous_mosaic_beta_mixture_distribution_XMLParser> {
public:
	continuous_mosaic_beta_mixture_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="continuous_mosaic_mixture_distribution">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="p" type="xs:string" use="required"/>
			<xs:attribute name="m" type="xs:string" use="required"/>
			<xs:attribute name="marginal" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
 */
class continuous_mosaic_mixture_distribution_XMLParser : public DAGXMLParserTemplate<continuous_mosaic_mixture_distribution_XMLParser> {
public:
	continuous_mosaic_mixture_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};
	
/*	<xs:element name="continuous_mixture">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="p" type="xs:string" use="required"/>
			<xs:attribute name="distribution0" type="xs:string" use="required"/>
			<xs:attribute name="distribution1" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
 */
class continuous_mixture_XMLParser : public DAGXMLParserTemplate<continuous_mixture_XMLParser> {
public:
	continuous_mixture_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="continuous_vector_distribution" substitutionGroup="abstract_distribution">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="marginal" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
*/
	class continuous_vector_distribution_XMLParser : public DAGXMLParserTemplate<continuous_vector_distribution_XMLParser> {
	public:
		continuous_vector_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
	};

/*	<xs:element name="gamma_distribution">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="shape" type="xs:string" use="required"/>
			<xs:attribute name="scale" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
 */
class gamma_distribution_XMLParser : public DAGXMLParserTemplate<gamma_distribution_XMLParser> {
public:
	gamma_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="improper_beta_distribution">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="a" type="xs:double" default="0.0"/>
			<xs:attribute name="b" type="xs:double" default="0.0"/>
		</xs:complexType>
	</xs:element>
 */
class improper_beta_distribution_XMLParser : public DAGXMLParserTemplate<improper_beta_distribution_XMLParser> {
public:
	improper_beta_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="improper_log_uniform_distribution">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
 */
class improper_log_uniform_distribution_XMLParser : public DAGXMLParserTemplate<improper_log_uniform_distribution_XMLParser> {
public:
	improper_log_uniform_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="improper_uniform_distribution">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
 */
class improper_uniform_distribution_XMLParser : public DAGXMLParserTemplate<improper_uniform_distribution_XMLParser> {
public:
	improper_uniform_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="inverse_gamma_distribution">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="shape" type="xs:string" use="required"/>
			<xs:attribute name="scale" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
 */
class inverse_gamma_distribution_XMLParser : public DAGXMLParserTemplate<inverse_gamma_distribution_XMLParser> {
public:
	inverse_gamma_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="log_normal_distribution">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="mean" type="xs:string" default="0.0"/>
			<xs:attribute name="sd" type="xs:string" default="1.0"/>
		</xs:complexType>
	</xs:element>
 */
class log_normal_distribution_XMLParser : public DAGXMLParserTemplate<log_normal_distribution_XMLParser> {
public:
	log_normal_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="log_uniform_distribution">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="min" type="xs:string" use="required"/>
			<xs:attribute name="max" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
 */
class log_uniform_distribution_XMLParser : public DAGXMLParserTemplate<log_uniform_distribution_XMLParser> {
public:
	log_uniform_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="normal_distribution">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="mean" type="xs:string" default="0.0"/>
			<xs:attribute name="sd" type="xs:string" default="1.0"/>
		</xs:complexType>
	</xs:element>
 */
class normal_distribution_XMLParser : public DAGXMLParserTemplate<normal_distribution_XMLParser> {
public:
	normal_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="uniform_distribution">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="min" type="xs:string" default="0.0"/>
			<xs:attribute name="max" type="xs:string" default="1.0"/>
		</xs:complexType>
	</xs:element>
 */
class uniform_distribution_XMLParser : public DAGXMLParserTemplate<uniform_distribution_XMLParser> {
public:
	uniform_distribution_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="distributions">
		<xs:complexType>
			<xs:choice minOccurs="0" maxOccurs="unbounded">
				<xs:element ref="beta_distribution"/>
				<xs:element ref="binomial_distribution"/>
			</xs:choice>
		</xs:complexType>
	</xs:element>
 */
class distributions_XMLParser : public DAGXMLParserTemplate<distributions_XMLParser>  {
public:
	distributions_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<distributions_XMLParser>(master_parser,parent_parser) {};
};	

void LoadDistributionsXML();
	
} // namespace gcat

#endif //_DISTRIBUTIONS_XML_H_
