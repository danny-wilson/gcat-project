/*  Copyright 2012 Daniel Wilson.
 *
 *  mainmpi.cpp
 *  Part of GCAT (General Computational Analysis Tool).
 *
 *  GCAT is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  GCAT is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with GCAT. If not, see <http://www.gnu.org/licenses/>.
 */
#define _MYUTILS_MPI_ABORT_ON_EXIT
#include <iostream>
#include <sstream>
#include <DAG/DAG.h>
#include <DAG/XML.h>
#include <mpi.h>
#include <gsl/gsl_errno.h>

using std::stringstream;
using std::exception;

// MPI globals
int MPI_ntasks;
int MPI_taskid;

//*** gcat (General Computational Analysis Tool ***//
int main (int argc, char * argv[]) {
	try {
		gsl_set_error_handler_off();

		// Initialize MPI
		int mpiargc = 1;
		MPI_Init(&mpiargc,&argv);
		int MPI_init;
		MPI_Initialized(&MPI_init);
		if(!(bool)MPI_init) error("MPI has not been initialized");
		MPI_Comm_size(MPI_COMM_WORLD,&MPI_ntasks);
		MPI_Comm_rank(MPI_COMM_WORLD,&MPI_taskid);
		cout << "Task " << MPI_taskid << " of " << MPI_ntasks << endl;
		
		DAG* dag = new DAG;
		
		if(argc!=2) error("SYNTAX: gcat.mpi xmlfile");
		stringstream xmlfile;
		xmlfile << argv[1] << "." << MPI_taskid;
		dag->readXML(xmlfile.str().c_str());
		
		dag->connect_graph();
		dag->check_validity();
		
		bool wait = true;
		while(!wait) {
		}
		
		dag->perform_inference();
		
		// Finalize MPI
		MPI_Finalize();	
	}
	catch (exception &e) {
		cout << "Uncaught exception:" << endl;
		cout << e.what() << endl;
	}
	catch (...) {
		cout << "Uncaught unknown exception" << endl;
	}
	return 0;
}


