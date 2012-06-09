/*  Copyright 2012 Daniel Wilson.
 *
 *  PowellML.h
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
#ifndef _MAXIMUM_LIKELIHOOD_H_
#define _MAXIMUM_LIKELIHOOD_H_

// From brent.h and powell.h
#include <limits>
#include <myerror.h>
//
#include <DAG/DAG.h>
#include <vector>
#include <random.h>
#include <fstream>
#include <ostream>
#include <matrix.h>
#include <RandomVariables/Continuous.h>

using std::vector;
using myutils::Random;
using std::ostream;
using std::ofstream;
using myutils::Matrix;

namespace gcat {

/*	Class Brent performs parabolic interpolation and Brent's method on a one-
 dimensional member function, BrentFunc.f(x). BrentFunc must be an instance of a class
 derived from the abstract class BrentFunction. Its member function f(x) takes only a
 single parameter, but using a derived class allows for it to be controlled by other
 member variables and/or call other member functions, enabling a neater alternative to
 using function pointers and global variables.
 
 See Numerical Recipes in C++ [Press et al 2002] for details of the algorithm.
 */

class BrentFunction {
public:
	virtual double f(const double x) = 0;
};

/*	An example derived class might look like MyFunction below. By passing an instance of
 MyFunction to an instance of Brent in its constructor, the function MyFunction::f(x)
 can be minimized with respect to x, whilst having an auxilliary variable y, which is not
 minimized.
 
 class MyFunction : public BrentFunction {
 double y;
 
 public:
 MyFunction(const double y_in) : y(y_in) {}
 double f(const double x) {
 return (x+y)*(x+y);
 }
 };
 */

class Brent {
public:
	BrentFunction & BrentFunc;
	
	bool coutput;
	double evala_BrentFunc, evalb_BrentFunc, evalc_BrentFunc;
	double pointa,pointb,pointc;
	double GLIMIT, TINY, tolerance;
	int ITMAX;
	double ZEPS,EPS;
	double function_minimum;
	bool bracketed;
	
public:
	Brent(BrentFunction &BrentFunc_in);
	double minimize(const double pointa_in, const double pointb_in, const double tol);
	double rootfind(double x1, double x2, double tol);
protected:
	/*	The hard work is done by algorithms modified from
	 Numerical Recipes in C++ [Press et al 2002]		*/
	inline void shft3(double &a, double &b, double &c, const double d);
	inline void shft2(double &a, double &b, const double c);
	void mnbrak(double &ax, double &bx, double &cx, double &fa, double &fb, double &fc);
	inline void SWAP(double &a, double &b);
	inline double SIGN(const double &a, const double &b);
	inline double MAX(const double &a, const double &b);
	inline double FABS(const double &a);
	double brent(const double ax, const double bx, const double cx, double &xmin);	
};

class ConstrainedBrent {
public:
	BrentFunction & BrentFunc;
	
	bool coutput;
	double evala_BrentFunc, evalb_BrentFunc, evalc_BrentFunc;
	double pointa,pointb,pointc;
	double GLIMIT, TINY, tolerance;
	int ITMAX;
	double ZEPS;
	double function_minimum;
	double min_x,max_x;
	
public:
	ConstrainedBrent(BrentFunction &BrentFunc_in);
	double minimize(const double pointa_in, const double pointb_in, const double tol, const double min_x_in, const double max_x_in);
protected:
	/*	The hard work is done by algorithms modified from
	 Numerical Recipes in C++ [Press et al 2002]		*/
	inline void shft3(double &a, double &b, double &c, const double d);
	inline void shft2(double &a, double &b, const double c);
	void mnbrak(double &ax, double &bx, double &cx, double &fa, double &fb, double &fc);
	inline void SWAP(double &a, double &b);
	inline double SIGN(const double &a, const double &b);
	inline double MAX(const double &a, const double &b);
	inline double FABS(const double &a);
	double brent(const double ax, const double bx, const double cx, double &xmin);	
};

class PowellFunction {
public:
	virtual double f(const vector<double>& x) = 0;
};

class Powell : public BrentFunction {
public:
	PowellFunction &PowFunc;
	Brent brent;
	
	bool coutput;
	int ITMAX;					// maximum number of iterations
	double TINY;				// a small number
	double TOL;					// tolerance
	
	int N;						// number of dimensions [= p.size()]
	vector<double> p;			// parameter vector for minimum of PowFunc.f()
	Matrix<double> xi;			// Matrix of vector directions
	double function_minimum;	// value of PowFunc.f() at its minimum
	int n_iterations;			// number of iterations taken to find function_minimum
	
	//	int BrentFunc_i;			// the column in xi that is being minimized one-dimensionally
	vector<double> BrentFunc_xt;// parameters to be fed into one-dimensional minimization
	vector<double> BrentFunc_xi;
	
public:
	Powell(PowellFunction &PowFunc_in);
	const vector<double>& minimize(const vector<double>& parameters, const double tol);
	double f(const double x);
protected:
	void powell(const double ftol, int &iter, double &fret);
	inline double linmin();
	inline double FABS(const double &a);
	inline double SQR(const double a);
};

class PowellML : public InferenceTechnique, protected PowellFunction {
protected:
	// Pointer to DAG
	DAG* _dag;
	// Target variables
	vector< ContinuousRV* > _target;

public:
	// Constructor
	PowellML(DAG* dag, vector< string > &target);
	// Destructor
	virtual ~PowellML();
	// Go! Implements pure virtual function in base class
	void perform_inference();
	// Pointer to DAG
	DAG* dag();
	// Targets
	vector<string> targets() const;
	
protected:
	/* Call PowellFunction::f() */
	double f(const vector<double> &x);
};

// Inline function definitions
inline void Brent::shft3(double &a, double &b, double &c, const double d) {
	a=b;	b=c;	c=d;
}
inline void Brent::shft2(double &a, double &b, const double c) {
	a=b;	b=c;
}
inline void Brent::SWAP(double &a, double &b) {
	double dum=a;a=b;b=dum;
}
inline double Brent::SIGN(const double &a, const double &b) {
	return b >= 0 ? (a >= 0 ? a : -a) : (a >= 0 ? -a : a);
}
inline double Brent::MAX(const double &a, const double &b) {
	return b > a ? (b) : (a);
}
inline double Brent::FABS(const double &a) {
	return a < 0.0 ? -a : a;
}

inline void ConstrainedBrent::shft3(double &a, double &b, double &c, const double d) {
	a=b;	b=c;	c=d;
}
inline void ConstrainedBrent::shft2(double &a, double &b, const double c) {
	a=b;	b=c;
}
inline void ConstrainedBrent::SWAP(double &a, double &b) {
	double dum=a;a=b;b=dum;
}
inline double ConstrainedBrent::SIGN(const double &a, const double &b) {
	return b >= 0 ? (a >= 0 ? a : -a) : (a >= 0 ? -a : a);
}
inline double ConstrainedBrent::MAX(const double &a, const double &b) {
	return b > a ? (b) : (a);
}
inline double ConstrainedBrent::FABS(const double &a) {
	return a < 0.0 ? -a : a;
}

inline double Powell::linmin() {
	double xmin,fret;
	xmin = brent.minimize(0.0,1.0,TOL);
	fret = brent.function_minimum;
	for(int j=0;j<N;j++) {
		BrentFunc_xi[j] *= xmin;
		p[j] += BrentFunc_xi[j];
	}
	return fret;
}

inline double Powell::FABS(const double &a) {
	return a < 0.0 ? -a : a;
}

inline double Powell::SQR(const double a) {
	return a*a;
}
	
} // namespace gcat

#endif //_MAXIMUM_LIKELIHOOD_H_
