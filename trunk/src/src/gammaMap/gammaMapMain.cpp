/*  Copyright 2012 Daniel Wilson.
 *
 *  gammaMapMain.cpp
 *  Part of gammaMap.
 *
 *  gammaMap is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  gammaMap is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with gammaMap. If not, see <http://www.gnu.org/licenses/>.
 */
#include <DAG/DAG.h>
#include <gammaMap/gammaMapXML.h>
#include <exception>

#ifdef main
#  error main is defined
#endif

//*** gammaMap ***//
int main (int argc, char * const argv[]) {
	try {	
		// Read the command line arguments
		if(argc!=2) error("SYNTAX: gcat xmlfile");
		const char* xmlfile = argv[1];

		// Instantiate the DAG
		gcat::DAG* dag = new gcat::DAG;
		// Set the root node for the XML file
		dag->add_root_element("gammaMap");
		// Do not permit in the XML file the section <libraries> <library file="XXX"/> ... </libraries>
		//dag->enable_libraries();
		// Load the core XML schema parser functions
		gcat::load_gcat_core_library();
		// Load the gammaMap XML schema parser functions
		gcat_gammaMap::load_gammaMap_library();
		// Read the XML file, using the schema specified therein
		dag->readXML(xmlfile);

		// Build the DAG
		dag->connect_graph();
		dag->check_validity();
		
		// Perform inference
		dag->perform_inference();
	}
	catch (std::exception &e) {
		error(e.what());
	}
	catch (...) {
		error("Unknown exception");
	}
	return 0;
}

