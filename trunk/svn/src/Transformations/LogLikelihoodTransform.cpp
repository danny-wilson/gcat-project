/*  Copyright 2012 Daniel Wilson.
 *
 *  LogLikelihoodTransform.cpp
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
#include <DAG/RandomVariable.h>
#include <Transformations/LogLikelihoodTransform.h>

namespace gcat {

const string LogLikelihoodTransformParameterNames[1] = {"rv"};

LogLikelihoodTransform::LogLikelihoodTransform(string name, DAG* dag) : DAGcomponent(name,dag,"LogLikelihoodTransform"), Transformation(LogLikelihoodTransformParameterNames,1) {
}

LogLikelihoodTransform::LogLikelihoodTransform(const LogLikelihoodTransform& x) : DAGcomponent(x), Transformation(x) {
}

double LogLikelihoodTransform::get_double() const {
	return get_rv()->log_likelihood();
}

bool LogLikelihoodTransform::check_parameter_type(const int i, Variable* parameter) {
	switch(i) {
		case 0:	// rv
			return(dynamic_cast<RandomVariable*>(parameter));
		default:
			error("LogLikelihoodTransform::check_parameter_type(): parameter not found");
	}
	return false;
}

void LogLikelihoodTransform::set_rv(RandomVariable* rv) {
	set_parameter(0,(Variable*)rv);
}

RandomVariable* LogLikelihoodTransform::get_rv() const {
	return (RandomVariable*)get_parameter(0);
}
	
} // namespace gcat

