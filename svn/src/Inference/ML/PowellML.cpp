/*  Copyright 2012 Daniel Wilson.
 *  Uses public domain functions from Numerical Recipes in C++, Second Edition by WH Press, SA Teukolsky, WT Vetterling and BP Flannery. Cambridge University Press (2002).
 *
 *  PowellML.cpp
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
#include <Inference/ML/PowellML.h>
#include <limits>
#include <myerror.h>
#include <vector>
#include <math.h>
#include <myutils.h>

using namespace std;
using namespace myutils;

namespace gcat {

Brent::Brent(BrentFunction &BrentFunc_in) : BrentFunc(BrentFunc_in), GLIMIT(100.), TINY(1.e-20), ITMAX(100), coutput(false), EPS(3.0e-8) {
}

double Brent::minimize(const double pointa_in, const double pointb_in, const double tol) {
	ZEPS=numeric_limits<double>::epsilon()*1.0e-3;
	pointa = pointa_in;
	pointb = pointb_in;
	pointc = 0.0;
	tolerance = tol;
	mnbrak(pointa, pointb, pointc, evala_BrentFunc, evalb_BrentFunc, evalc_BrentFunc);
	if(coutput) {
		cout << "Function is bracketed by:" << endl;
		cout << "f(" << pointa << ") = " << evala_BrentFunc << endl;
		cout << "f(" << pointb << ") = " << evalb_BrentFunc << endl;
		cout << "f(" << pointc << ") = " << evalc_BrentFunc << endl;
	}
	double result = 0.0;
	function_minimum = brent(pointa, pointb, pointc, result);
	if(coutput)
		cout << "Function is minimized at f(" << result << ") = " << function_minimum << endl;
	return result;
}

double Brent::rootfind(double x1, double x2, double tol) {
	//Using Brent's method, find the root of a function func known to lie between x1 and x2. The
	//root, returned as zbrent, will be refined until its accuracy is tol.
	int iter;
	double a=x1,b=x2,c=x2,d,e,min1,min2;
	double fa=BrentFunc.f(a),fb=BrentFunc.f(b),fc,p,q,r,s,tol1,xm;
	bracketed = true;
	if ((fa > 0.0 && fb > 0.0) || (fa < 0.0 && fb < 0.0)) {
		if(coutput)
			cout << "f(" << x1 << ") = " << fa << "\tf(" << x2 << ") = " << fb << endl;
		//myutils::warning("Root must be bracketed in rootfind");
		bracketed = false;
		return 0.0;
	}
	fc=fb;
	for (iter=1;iter<=ITMAX;iter++) {
		if ((fb > 0.0 && fc > 0.0) || (fb < 0.0 && fc < 0.0)) {
			c=a; //Rename a, b, c and adjust bounding interval d.
			fc=fa;
			e=d=b-a;
		}
		if (fabs(fc) < fabs(fb)) {
			a=b;
			b=c;
			c=a;
			fa=fb;
			fb=fc;
			fc=fa;
		}
		tol1=2.0*EPS*fabs(b)+0.5*tol; //Convergence check.
		xm=0.5*(c-b);
		if (fabs(xm) <= tol1 || fb == 0.0) return b;
		if (fabs(e) >= tol1 && fabs(fa) > fabs(fb)) {
			s=fb/fa; //Attempt inverse quadratic interpolation.
			if (a == c) {
				p=2.0*xm*s;
				q=1.0-s;
			} else {
				q=fa/fc;
				r=fb/fc;
				p=s*(2.0*xm*q*(q-r)-(b-a)*(r-1.0));
				q=(q-1.0)*(r-1.0)*(s-1.0);
			}
			if (p > 0.0) q = -q; //Check whether in bounds.
			p=fabs(p);
			min1=3.0*xm*q-fabs(tol1*q);
			min2=fabs(e*q);
			if (2.0*p < (min1 < min2 ? min1 : min2)) {
				e=d; //Accept interpolation.
				d=p/q;
			} else {
				d=xm; //Interpolation failed, use bisection.
				e=d;
			}
		} else { //Bounds decreasing too slowly, use bisection.
			d=xm;
			e=d;
		}
		a=b; //Move last best guess to a.
		fa=fb;
		if (fabs(d) > tol1) //Evaluate new trial root.
			b += d;
		else
			b += SIGN(tol1,xm);
		fb=BrentFunc.f(b);
	}
	myutils::warning("Maximum number of iterations exceeded in zbrent");
	return 0.0; //Never get here.
}

void Brent::mnbrak(double &ax, double &bx, double &cx, double &fa, double &fb, double &fc) {
	const double GOLD=1.618034;
	double ulim,u,r,q,fu;
	
	fa = BrentFunc.f(ax);
	fb = BrentFunc.f(bx);
	if (fb > fa) {
		SWAP(ax,bx);
		SWAP(fb,fa);
	}
	cx=bx+GOLD*(bx-ax);
	fc=BrentFunc.f(cx);
	while (fb > fc) {
		r=(bx-ax)*(fb-fc);
		q=(bx-cx)*(fb-fa);
		u=bx-((bx-cx)*q-(bx-ax)*r)/
		(2.0*SIGN(MAX(FABS(q-r),TINY),q-r));
		ulim=bx+GLIMIT*(cx-bx);
		if ((bx-u)*(u-cx) > 0.0) {
			fu=BrentFunc.f(u);
			if (fu < fc) {
				ax=bx;
				bx=u;
				fa=fb;
				fb=fu;
				return;
			} else if (fu > fb) {
				cx=u;
				fc=fu;
				return;
			}
			u=cx+GOLD*(cx-bx);
			fu=BrentFunc.f(u);
		} else if ((cx-u)*(u-ulim) > 0.0) {
			fu=BrentFunc.f(u);
			if (fu < fc) {
				shft3(bx,cx,u,cx+GOLD*(cx-bx));
				shft3(fb,fc,fu,BrentFunc.f(u));
			}
		} else if ((u-ulim)*(ulim-cx) >= 0.0) {
			u=ulim;
			fu=BrentFunc.f(u);
		} else {
			u=cx+GOLD*(cx-bx);
			fu=BrentFunc.f(u);
		}
		shft3(ax,bx,cx,u);
		shft3(fa,fb,fc,fu);
	}
}

double Brent::brent(const double ax, const double bx, const double cx, double &xmin)
{
	const double CGOLD=0.3819660;
	int iter;
	double a,b,d=0.0,etemp,fu,fv,fw,fx;
	double p,q,r,tol1,tol2,u,v,w,x,xm;
	double e=0.0;
	
	a=(ax < cx ? ax : cx);
	b=(ax > cx ? ax : cx);
	x=w=v=bx;
	fw=fv=fx=BrentFunc.f(x);
	for (iter=0;iter<ITMAX;iter++) {
		xm=0.5*(a+b);
		tol2=2.0*(tol1=tolerance*FABS(x)+ZEPS);
		if (FABS(x-xm) <= (tol2-0.5*(b-a))) {
			xmin=x;
			return fx;
		}
		if (FABS(e) > tol1) {
			r=(x-w)*(fx-fv);
			q=(x-v)*(fx-fw);
			p=(x-v)*q-(x-w)*r;
			q=2.0*(q-r);
			if (q > 0.0) p = -p;
			q=FABS(q);
			etemp=e;
			e=d;
			if (FABS(p) >= FABS(0.5*q*etemp) || p <= q*(a-x) || p >= q*(b-x))
				d=CGOLD*(e=(x >= xm ? a-x : b-x));
			else {
				d=p/q;
				u=x+d;
				if (u-a < tol2 || b-u < tol2)
					d=SIGN(tol1,xm-x);
			}
		} else {
			d=CGOLD*(e=(x >= xm ? a-x : b-x));
		}
		u=(FABS(d) >= tol1 ? x+d : x+SIGN(tol1,d));
		fu=BrentFunc.f(u);
		if (fu <= fx) {
			if (u >= x) a=x; else b=x;
			shft3(v,w,x,u);
			shft3(fv,fw,fx,fu);
		} else {
			if (u < x) a=u; else b=u;
			if (fu <= fw || w == x) {
				v=w;
				w=u;
				fv=fw;
				fw=fu;
			} else if (fu <= fv || v == x || v == w) {
				v=u;
				fv=fu;
			}
		}
	}
	myutils::error("Brent: Too many iterations");
	xmin=x;
	return fx;
}

ConstrainedBrent::ConstrainedBrent(BrentFunction &BrentFunc_in) : BrentFunc(BrentFunc_in), GLIMIT(100.), TINY(1.e-20), ITMAX(100), coutput(false) {
}

double ConstrainedBrent::minimize(const double pointa_in, const double pointb_in, const double tol, const double min_x_in, const double max_x_in) {
	min_x = min_x_in;
	max_x = max_x_in;
	ZEPS=numeric_limits<double>::epsilon()*1.0e-3;
	pointa = pointa_in;
	pointb = pointb_in;
	pointc = min_x;
	
	if(pointa<min_x || pointa>max_x) error("ConstrainedBrent::minimize(): point a falls outside range");
	if(pointb<min_x || pointb>max_x) error("ConstrainedBrent::minimize(): point b falls outside range");
	
	tolerance = tol;
	mnbrak(pointa, pointb, pointc, evala_BrentFunc, evalb_BrentFunc, evalc_BrentFunc);
	if(coutput) {
		cout << "Function is bracketed by:" << endl;
		cout << "f(" << pointa << ") = " << evala_BrentFunc << endl;
		cout << "f(" << pointb << ") = " << evalb_BrentFunc << endl;
		cout << "f(" << pointc << ") = " << evalc_BrentFunc << endl;
	}
	double result = 0.0;
	function_minimum = brent(pointa, pointb, pointc, result);
	if(coutput)
		cout << "Function is minimized at f(" << result << ") = " << function_minimum << endl;
	return result;
}

void ConstrainedBrent::mnbrak(double &ax, double &bx, double &cx, double &fa, double &fb, double &fc) {
	const double GOLD=1.618034;
	double ulim,u,r,q,fu;
	
	fa = BrentFunc.f(ax);
	fb = BrentFunc.f(bx);
	if (fb > fa) {
		SWAP(ax,bx);
		SWAP(fb,fa);
	}
	cx=bx+GOLD*(bx-ax);
	if(cx<min_x) cx = min_x;
	if(cx>max_x) cx = max_x;
	
	fc=BrentFunc.f(cx);
	while (fb > fc) {
		r=(bx-ax)*(fb-fc);
		q=(bx-cx)*(fb-fa);
		u=bx-((bx-cx)*q-(bx-ax)*r)/
		(2.0*SIGN(MAX(FABS(q-r),TINY),q-r));
		if(u<min_x) u = min_x;
		if(u>max_x) u = max_x;
		ulim=bx+GLIMIT*(cx-bx);
		if ((bx-u)*(u-cx) > 0.0) {
			fu=BrentFunc.f(u);
			if (fu < fc) {
				ax=bx;
				bx=u;
				fa=fb;
				fb=fu;
				return;
			} else if (fu > fb) {
				cx=u;
				fc=fu;
				return;
			}
			u=cx+GOLD*(cx-bx);
			if(u<min_x) u = min_x;
			if(u>max_x) u = max_x;
			fu=BrentFunc.f(u);
		} else if ((cx-u)*(u-ulim) > 0.0) {
			fu=BrentFunc.f(u);
			if (fu < fc) {
				shft3(bx,cx,u,cx+GOLD*(cx-bx));
				if(u<min_x) u = min_x;
				if(u>max_x) u = max_x;
				shft3(fb,fc,fu,BrentFunc.f(u));
			}
		} else if ((u-ulim)*(ulim-cx) >= 0.0) {
			u=ulim;
			if(u<min_x) u = min_x;
			if(u>max_x) u = max_x;
			fu=BrentFunc.f(u);
		} else {
			u=cx+GOLD*(cx-bx);
			if(u<min_x) u = min_x;
			if(u>max_x) u = max_x;
			fu=BrentFunc.f(u);
		}
		shft3(ax,bx,cx,u);
		shft3(fa,fb,fc,fu);
	}
}

double ConstrainedBrent::brent(const double ax, const double bx, const double cx, double &xmin) {
	const double CGOLD=0.3819660;
	int iter;
	double a,b,d=0.0,etemp,fu,fv,fw,fx;
	double p,q,r,tol1,tol2,u,v,w,x,xm;
	double e=0.0;
	
	a=(ax < cx ? ax : cx);
	b=(ax > cx ? ax : cx);
	x=w=v=bx;
	
	fw=fv=fx=BrentFunc.f(x);
	for (iter=0;iter<ITMAX;iter++) {
		xm=0.5*(a+b);
		tol2=2.0*(tol1=tolerance*FABS(x)+ZEPS);
		if (FABS(x-xm) <= (tol2-0.5*(b-a))) {
			xmin=x;
			return fx;
		}
		if (FABS(e) > tol1) {
			r=(x-w)*(fx-fv);
			q=(x-v)*(fx-fw);
			p=(x-v)*q-(x-w)*r;
			q=2.0*(q-r);
			if (q > 0.0) p = -p;
			q=FABS(q);
			etemp=e;
			e=d;
			if (FABS(p) >= FABS(0.5*q*etemp) || p <= q*(a-x) || p >= q*(b-x))
				d=CGOLD*(e=(x >= xm ? a-x : b-x));
			else {
				d=p/q;
				u=x+d;
				if (u-a < tol2 || b-u < tol2)
					d=SIGN(tol1,xm-x);
			}
		} else {
			d=CGOLD*(e=(x >= xm ? a-x : b-x));
		}
		u=(FABS(d) >= tol1 ? x+d : x+SIGN(tol1,d));
		fu=BrentFunc.f(u);
		if (fu <= fx) {
			if (u >= x) a=x; else b=x;
			shft3(v,w,x,u);
			shft3(fv,fw,fx,fu);
		} else {
			if (u < x) a=u; else b=u;
			if (fu <= fw || w == x) {
				v=w;
				w=u;
				fv=fw;
				fw=fu;
			} else if (fu <= fv || v == x || v == w) {
				v=u;
				fv=fu;
			}
		}
	}
	myutils::error("Brent: Too many iterations");
	xmin=x;
	return fx;
}

Powell::Powell(PowellFunction &PowFunc_in) : PowFunc(PowFunc_in), ITMAX(200), TINY(1.0e-25), TOL(1.0e-8), coutput(false), brent(*this) {
}

const vector<double>& Powell::minimize(const vector<double>& parameters, const double tol) {
	p = parameters;
	n_iterations = 0;
	N = parameters.size();
	xi = Matrix<double>(N,N,0.0);
	int i;
	for(i=0;i<N;i++) xi[i][i] = 1.;
	powell(tol, n_iterations, function_minimum);
	if(coutput) {
		cout << "Function is minimized at f(";
		for(i=0;i<N;i++) cout << p[i] << " ";
		cout << "\b) = " << function_minimum << endl;
	}
	return p;
}

double Powell::f(const double x) {
	for(int j=0;j<N;j++)
		BrentFunc_xt[j] = p[j] + x * BrentFunc_xi[j];
	return PowFunc.f(BrentFunc_xt);
}

void Powell::powell(const double ftol, int &iter, double &fret) {
	int i,j,ibig;
	double del,fp,fptt,t;
	
	BrentFunc_xt = vector<double>(N);
	BrentFunc_xi = vector<double>(N);
	
	vector<double> pt = p;
	vector<double> ptt(N);//,xit(N);
	fret = PowFunc.f(p);
	
	for (iter=0;;++iter) {
		fp=fret;
		ibig=0;
		del=0.0;
		for (i=0;i<N;i++) {
			for (j=0;j<N;j++) BrentFunc_xi[j]=xi[j][i]; /*copying is so we can minimize along this direction*/
			fptt=fret;
			fret = linmin();
			if (fptt-fret > del) {
				del=fptt-fret;
				ibig=i+1;
			}
		}
		if (2.0*(fp-fret) <= ftol*(FABS(fp)+FABS(fret))+TINY) {
			return;
		}
		if (iter == ITMAX) error("Powell: Too many iterations");
		for (j=0;j<N;j++) {
			ptt[j]=2.0*p[j]-pt[j];
			BrentFunc_xi[j]=p[j]-pt[j];
			pt[j]=p[j];
		}
		fptt=PowFunc.f(ptt);
		if (fptt < fp) {
			t=2.0*(fp-2.0*fret+fptt)*SQR(fp-fret-del)-del*SQR(fp-fptt);
			if (t < 0.0) {
				fret = linmin();
				for (j=0;j<N;j++) {
					xi[j][ibig-1]=xi[j][N-1];
					xi[j][N-1]=BrentFunc_xi[j];
				}
			}
		}
	}
}

PowellML::PowellML(DAG* dag, vector< string > &target) : _dag(dag), _target(0) {
	if(target.size()==0) error("MCMC_move: no targets");
	int i;
	for(i=0;i<target.size();i++) {
		RandomVariable* var = _dag->get_random_variable(target[i]);
		ContinuousRV* cvar = dynamic_cast<ContinuousRV*>(var);
		if(!cvar) {
			string errTxt = "PowellML: Random variable " + var->name() + " has type " + var->type() + " not ContinuousRV";
			error(errTxt.c_str());
		}
		_target.push_back(cvar);
	}
	dag->set_inference_technique(this);
}

PowellML::~PowellML() {
}

void PowellML::perform_inference() {
	Powell pow(*this);
	pow.coutput = true;
	vector<double> x(_target.size());
	int i;
	for(i=0;i<x.size();i++) {
		x[i] = _target[i]->get_double();
	}
	vector<double> res = pow.minimize(x,1.0e-6);
	cout << "Maximum likelihood estimates:" << endl;
	for(i=0;i<res.size();i++) {
		cout << _target[i]->name() << "\t=\t" << res[i] << endl;
	}
	cout << endl;
}

DAG* PowellML::dag() {
	return _dag;
}

vector<string> PowellML::targets() const {
	vector<string> ret(_target.size());
	int i;
	for(i=0;i<ret.size();i++) ret[i] = _target[i]->name();
	return ret;
}

double PowellML::f(const vector<double> &x) {
	if(x.size()!=_target.size()) error("PowellML::f(): vector of wrong size");
	int i;
	for(i=0;i<x.size();i++) {
		_target[i]->set(x[i]);
	}
	return -_dag->likelihood().LOG();
}
	
} // namespace gcat
