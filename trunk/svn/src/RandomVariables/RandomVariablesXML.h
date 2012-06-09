/*  Copyright 2012 Daniel Wilson.
 *
 *  RandomVariablesXML.h
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
#ifndef _VARIABLES_XML_H_
#define _VARIABLES_XML_H_
#include <DAG/DAGXMLParser.h>

namespace gcat {

/*	<xs:element name="continuous_scalar">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="distribution" type="xs:string" default=""/>
			<xs:attribute name="value" type="xs:decimal" default="0"/>
		</xs:complexType>
	</xs:element> 
 */
class continuous_scalar_XMLParser : public DAGXMLParserTemplate<continuous_scalar_XMLParser> {
public:
	continuous_scalar_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser, const bool constant=false);
// Specialized static member functions
	static DAGXMLParser* factory_constant(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) {
		return (DAGXMLParser*)(new continuous_scalar_XMLParser(uri,localname,qname,attrs,master_parser,parent_parser,true));
	}
};

/*	<xs:element name="continuous_mosaic">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="distribution" type="xs:string" default=""/>
			<xs:attribute name="length" type="xs:string" use="required"/>
			<xs:attribute name="boundaries" type="xs:string" default=""/>
			<xs:attribute name="values" type="xs:string" default=""/>
		</xs:complexType>
	</xs:element> 
 */
class continuous_mosaic_XMLParser : public DAGXMLParserTemplate<continuous_mosaic_XMLParser> {
public:
	continuous_mosaic_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser, const bool constant=false);
	// Specialized static member functions
	static DAGXMLParser* factory_constant(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) {
		return (DAGXMLParser*)(new continuous_mosaic_XMLParser(uri,localname,qname,attrs,master_parser,parent_parser,true));
	}
};

/*	<xs:element name="discrete_scalar">
		<xs:complexType>
			<xs:attribute name="id" type="xs:string" use="required"/>
			<xs:attribute name="distribution" type="xs:string" default=""/>
			<xs:attribute name="value" type="xs:integer" default="0"/>
		</xs:complexType>
	</xs:element>
 */
class discrete_scalar_XMLParser : public DAGXMLParserTemplate<discrete_scalar_XMLParser> {
public:
	discrete_scalar_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser, const bool constant=false);
	// Specialized static member functions
	static DAGXMLParser* factory_constant(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) {
		return (DAGXMLParser*)(new discrete_scalar_XMLParser(uri,localname,qname,attrs,master_parser,parent_parser,true));
	}
};

/*	<xs:simpleType name="decimal_list">
		<xs:list itemType="xs:decimal"/>
	</xs:simpleType>

	<xs:complexType name="continuous_vector_type">
		<xs:simpleContent>
			<xs:extension base="decimal_list">
				<xs:attribute name="id" type="xs:string" use="required"/>
				<xs:attribute name="distribution" type="xs:string" default=""/>
			</xs:extension>
		</xs:simpleContent>
	</xs:complexType>

	<xs:element name="iid_continuous_scalar" type="continuous_vector_type"/>
	<xs:element name="continuous_vector" type="continuous_vector_type"/>
*/
class iid_continuous_scalar_XMLParser : public DAGXMLParserTemplate<iid_continuous_scalar_XMLParser> {
	vector<string> sattr;
public:
	iid_continuous_scalar_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
	void implement_characters(const XMLCh* const chars, const XMLSize_t length);
};

class continuous_vector_XMLParser : public DAGXMLParserTemplate<continuous_vector_XMLParser> {
	bool _constant;
	vector<string> sattr;
public:
	continuous_vector_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser, const bool constant=false);
//	void characters(const XMLCh* const chars, const XMLSize_t length);
	void implement_characters(const XMLCh* const chars, const XMLSize_t length);
	// Specialized static member functions
	static DAGXMLParser* factory_constant(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) {
		return (DAGXMLParser*)(new continuous_vector_XMLParser(uri,localname,qname,attrs,master_parser,parent_parser,true));
	}
};

/*	<xs:simpleType name="integer_list">
		<xs:list itemType="xs:integer"/>
	</xs:simpleType>
 
	<xs:element name="iid_discrete_scalar">
		<xs:complexType>
			<xs:simpleContent>
				<xs:extension base="integer_list">
					<xs:attribute name="id" type="xs:string" use="required"/>
					<xs:attribute name="distribution" type="xs:string" default=""/>
				</xs:extension>
			</xs:simpleContent>
		</xs:complexType>
	</xs:element>
*/
class iid_discrete_scalar_XMLParser : public DAGXMLParserTemplate<iid_discrete_scalar_XMLParser> {
	vector<string> sattr;
public:
	iid_discrete_scalar_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser);
	void implement_characters(const XMLCh* const chars, const XMLSize_t length);
};

/*	<xs:complexType name="parameter_variables">
		<xs:choice minOccurs="0" maxOccurs="unbounded">
			<xs:element ref="continuous_scalar"/>
			<xs:element ref="continuous_vector"/>
			<xs:element ref="discrete_scalar"/>
			<xs:element ref="discrete_vector"/>
		</xs:choice>
	</xs:complexType>

	<xs:complexType name="data_variables">
		<xs:choice minOccurs="0" maxOccurs="unbounded">
			<xs:element ref="continuous_scalar"/>
			<xs:element ref="iid_continuous_scalar"/>
			<xs:element ref="discrete_scalar"/>
			<xs:element ref="iid_discrete_scalar"/>
		</xs:choice>
	</xs:complexType>

	<xs:element name="data" type="data_variables"/>
	<xs:element name="parameters" type="parameter_variables"/>
 */
class data_XMLParser : public DAGXMLParserTemplate<data_XMLParser> {
public:
	data_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<data_XMLParser>(master_parser,parent_parser) {};
};

class parameters_XMLParser : public DAGXMLParserTemplate<parameters_XMLParser> {
public:
	parameters_XMLParser(const XMLCh* const uri, const XMLCh* const localname, const XMLCh* const qname, const Attributes& attrs, DAGXMLMasterParser* const master_parser, DAGXMLParser* const parent_parser) : DAGXMLParserTemplate<parameters_XMLParser>(master_parser,parent_parser) {};
};

void LoadRandomVariablesXML();
	
} // namespace gcat

#endif //_VARIABLES_XML_H_
