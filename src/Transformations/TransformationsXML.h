/*  Copyright 2012 Daniel Wilson.
 *
 *  TransformationsXML.h
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
#ifndef _TRANSFORMATIONS_XML_H_
#define _TRANSFORMATIONS_XML_H_
#include <DAG/DAGXMLParser.h>

namespace gcat {

/***** CONVERSIONS *****/

/*	<xs:element name="to_continuous_mosaic">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="x" type="xs:string" use="required"/>
			<xs:attribute name="length" type="xs:string" default="1"/>
		</xs:complexType>
	</xs:element>
 */
class to_continuous_mosaic_XMLParser : public DAGXMLParserTemplate<to_continuous_mosaic_XMLParser> {
public:
	to_continuous_mosaic_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="to_continuous_vector">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="x" type="xs:string" use="required"/>
			<xs:attribute name="length" type="xs:string" default="1"/>
		</xs:complexType>
	</xs:element>
 */
class to_continuous_vector_XMLParser : public DAGXMLParserTemplate<to_continuous_vector_XMLParser> {
public:
	to_continuous_vector_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/***** ALL OTHER TRANSFORMATIONS *****/

/*	<xs:element name="abs_transform">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="x" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
*/
class abs_transform_XMLParser : public DAGXMLParserTemplate<abs_transform_XMLParser> {
public:
	abs_transform_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="concatenate">
		<xs:complexType>
			<xs:simpleContent>
				<xs:extension base="xs:string">
					<xs:attribute name="id" type="xs:string" use="required"/>
					<xs:attribute name="length" type="xs:string" use="required"/>
				</xs:extension>
			</xs:simpleContent>
		</xs:complexType>
	</xs:element>
 */
class concatenate_transform_XMLParser : public DAGXMLParserTemplate<concatenate_transform_XMLParser> {
	vector<string> sattr;
public:
	concatenate_transform_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
	void implement_characters(const XMLCh* const chars, const XMLSize_t length);
};

/* 	<xs:element name="continuous_mosaic_num_blocks">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="continuous_mosaic" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
*/ 
class continuous_mosaic_num_blocks_XMLParser : public DAGXMLParserTemplate<continuous_mosaic_num_blocks_XMLParser> {
public:
	continuous_mosaic_num_blocks_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="continuous_vector_element">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="vector" type="xs:string" use="required"/>
			<xs:attribute name="element" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element> 
 */
class continuous_vector_element_XMLParser : public DAGXMLParserTemplate<continuous_vector_element_XMLParser> {
public:
	continuous_vector_element_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="exp_transform">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="exponent" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
*/
class exp_transform_XMLParser : public DAGXMLParserTemplate<exp_transform_XMLParser> {
public:
	exp_transform_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="exponential_quantile_function_vector">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="lambda" type="xs:string" default="1"/>
			<xs:attribute name="quantile" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
*/
class exponential_quantile_function_vector_XMLParser : public DAGXMLParserTemplate<exponential_quantile_function_vector_XMLParser> {
public:
	exponential_quantile_function_vector_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="fraction_transform">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="numerator" type="xs:string" use="required"/>
			<xs:attribute name="denominator" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
 */
class fraction_transform_XMLParser : public DAGXMLParserTemplate<fraction_transform_XMLParser> {
public:
	fraction_transform_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="inverse_logit_transform">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="p" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
 */
class inverse_logit_transform_XMLParser : public DAGXMLParserTemplate<inverse_logit_transform_XMLParser> {
public:
	inverse_logit_transform_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="linear_mosaic_transform">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="mean" type="xs:string" default="0"/>
			<xs:attribute name="sd" type="xs:string" default="1"/>
			<xs:attribute name="z" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
 */
class linear_mosaic_transform_XMLParser : public DAGXMLParserTemplate<linear_mosaic_transform_XMLParser> {
public:
	linear_mosaic_transform_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="log_likelihood_transform">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="rv" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
 */
class log_likelihood_transform_XMLParser : public DAGXMLParserTemplate<log_likelihood_transform_XMLParser> {
public:
	log_likelihood_transform_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="power_transform">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="base" type="xs:string" use="required"/>
			<xs:attribute name="exponent" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
*/
class power_transform_XMLParser : public DAGXMLParserTemplate<power_transform_XMLParser> {
public:
	power_transform_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

/*	<xs:element name="product_transform">
		<xs:complexType>
			<xs:simpleContent>
				<xs:extension base="xs:string">
					<xs:attribute name="id" type="xs:string" use="required"/>
				</xs:extension>
			</xs:simpleContent>
		</xs:complexType>
	</xs:element>
 */
class product_transform_XMLParser : public DAGXMLParserTemplate<product_transform_XMLParser> {
	vector<string> sattr;
public:
	product_transform_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
	void implement_characters(const XMLCh* const chars, const XMLSize_t length);
};

/*	<xs:element name="proportion_transformation">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="u" type="xs:string" use="required"/>
			<xs:attribute name="v" type="xs:string" use="required"/>
		</xs:complexType>
	</xs:element>
 *
class proportion_transformation_XMLParser : public DAGXMLParser {
public:
	proportion_transformation_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParser(master_parser,parent_parser) {
		// Read in the attributes
		const int nattr = 3;
		const char* attrNames[nattr] = {"id","u","v"};
		vector<string> sattr = attributesToStrings(nattr,attrNames,attrs);
		// a and b can be specified as numeric, in which case they must be instantiated as Variables
		double double_u;
		if(from_string<double>(double_u,sattr[1])) {
			// Internally-generated name
			sattr[1] = "_" + sattr[0] + "." + attrNames[1];
			new ContinuousUnivariateVariable(sattr[1],getDAG(),double_u);
			getDAG()->set_constant(sattr[1]);
		}
		double double_v;
		if(from_string<double>(double_v,sattr[2])) {
			// Internally-generated name
			sattr[2] = "_" + sattr[0] + "." + attrNames[2];
			new ContinuousUnivariateVariable(sattr[2],getDAG(),double_v);
			getDAG()->set_constant(sattr[2]);
		}
		// Internally-generated name
		string tname = "_" + sattr[0] + ".transformation";
		new ProportionTransformation(tname,getDAG());
		getDAG()->assign_parameter_to_distribution(tname,attrNames[1],sattr[1]);
		getDAG()->assign_parameter_to_distribution(tname,attrNames[2],sattr[2]);
		new ContinuousUnivariateTransformedVariable(sattr[0],getDAG());
		getDAG()->assign_distribution_to_variable(sattr[0],"distribution",tname);
		getDAG()->set_constant(sattr[0]);
	}
};*/

/*	<xs:element name="sum_transform">
		<xs:complexType>
			<xs:simpleContent>
				<xs:extension base="xs:string">
					<xs:attribute name="id" type="xs:string" use="required"/>
				</xs:extension>
			</xs:simpleContent>
		</xs:complexType>
	</xs:element>
 */
class sum_transform_XMLParser : public DAGXMLParserTemplate<sum_transform_XMLParser> {
	vector<string> sattr;
public:
	sum_transform_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
	void implement_characters(const XMLCh* const chars, const XMLSize_t length);
};

/*	<xs:element name="transformations">
		<xs:complexType>
			<xs:choice minOccurs="0" maxOccurs="unbounded">
				<xs:element ref="proportion_transformation"/>
			</xs:choice>
		</xs:complexType>
	</xs:element>
 */
class transformations_XMLParser : public DAGXMLParserTemplate<transformations_XMLParser> {
public:
	transformations_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
};

void LoadTransformationsXML();
	
} // namespace gcat

#endif // _TRANSFORMATIONS_XML_H_
