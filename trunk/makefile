###################################################
#
# Makefile for gcat-project
#
###################################################

#
# Macros
#

# Header file locations for gcat-project
INCLUDE = -Isrc -Isrc/myutils
# C++ compiler
CC = g++
# C++ compiler for MPICH2
MPICC = mpic++
# C++ linker
LD = g++
# C++ standard compiler options
CXXFLAGS = -Wall -w -O0 -g -D __NOEXTERN_FOR_CINCLUDE 
# C++ compiler options for gcat library code
CC_OPTIONS = $(CXXFLAGS) -fPIC
# C++ linker options
#LNK_OPTIONS = -L/mnt/lustre/home/djw/xerces-c-3.0.1-x86_64-linux-gcc-3.4/lib\
#		-L/usr/lib64/mpich2\
#		-lxerces-c\
#		-lgsl\
#		-lgslcblas
LNK_OPTIONS = -lxerces-c

#
# Build gcat-project
#

GCAT_CORE_OBJECTS = \
		./Component.o\
		./DAG.o\
		./DAGreadXML.o\
		./DAGXMLParser.o\
		./DependentVariable.o\
		./Distribution.o\
		./RandomVariable.o\
		./Transformation.o\
		./Variable.o\
		./Beta.o\
		./Binomial.o\
		./ContinuousMixture.o\
		./Distribution_ContinuousMosaic.o\
		./Distribution_ContinuousMosaicBetaMixture.o\
		./Gamma.o\
		./ImproperBeta.o\
		./ImproperLogUniform.o\
		./ImproperUniform.o\
		./InverseGamma.o\
		./LogNormal.o\
		./LogUniform.o\
		./Normal.o\
		./Uniform.o\
		./DistributionsXML.o\
		./gcatLibrary.o\
		./ContinuousMosaicMoves.o\
		./InferenceXML.o\
		./MCMC.o\
		./PowellML.o\
		./Continuous.o\
		./RandomVariable_ContinuousMosaic.o\
		./ContinuousVector.o\
		./Discrete.o\
		./RandomVariablesXML.o\
		./AbsoluteTransform.o\
		./Concatenate.o\
		./ContinuousMosaicNumBlocks.o\
		./ContinuousVectorElement.o\
		./ExponentialQuantileVector.o\
		./ExponentialTransform.o\
		./FractionTransform.o\
		./InverseLogitTransform.o\
		./LinearMosaic.o\
		./LogLikelihoodTransform.o\
		./PowerTransform.o\
		./ProductTransform.o\
		./SumTransform.o\
		./TransformationsXML.o

LIB_GAMMAMAP_OBJECTS = \
		./Codon61SequenceStationaryDistribution.o\
		./gammaMapHMMHybrid.o\
		./gammaMapLibrary.o\
		./gammaMapMoves.o\
		./gammaMapXML.o\
		./Codon61Count.o\
		./Codon61Sequence.o\
		./gammaMapUtils.o\
		./mutation.o\
		./paml.o

all : libgammaMap.so libgcat-core.so gcat

gcat : gcatmain.o
	$(LD) $(LNK_OPTIONS) -L./ -lgcat-core -ldl -rdynamic gcatmain.o -o gcat

#gcat.mpi : mpimain.o MPIMoves.o MCMC_MPI_XML.o $(OBJECTS)
#	$(MPICC) $(LNK_OPTIONS) -lmpich mpimain.o MPIMoves.o MCMC_MPI_XML.o $(OBJECTS) -o gcat.mpi

clean : cleanobj
	rm gcat libgcat-core.so libgammaMap.so

cleanobj :
	rm gcatmain.o $(GCAT_CORE_OBJECTS) $(LIB_GAMMAMAP_OBJECTS)

#install : gcat
#		cp gcat gcat

libgcat-core.so : $(GCAT_CORE_OBJECTS)
	$(LD) $(LNK_OPTIONS) -shared -o libgcat-core.so $(GCAT_CORE_OBJECTS)

libgammaMap.so : $(LIB_GAMMAMAP_OBJECTS) libgcat-core.so
	$(LD) $(LNK_OPTIONS) -lgsl -L/home/wilson/svn/gcat-project/ -lgcat-core -shared -o libgammaMap.so $(LIB_GAMMAMAP_OBJECTS)

#
# Build the parts of gcat
#

./Component.o : src/DAG/Component.cpp
	$(CC) $(CC_OPTIONS) src/DAG/Component.cpp -c $(INCLUDE) -o ./Component.o

./DAG.o : src/DAG/DAG.cpp
	$(CC) $(CC_OPTIONS) src/DAG/DAG.cpp -c $(INCLUDE) -o ./DAG.o

./DAGreadXML.o : src/DAG/DAGreadXML.cpp
	$(CC) $(CC_OPTIONS) src/DAG/DAGreadXML.cpp -c $(INCLUDE) -o ./DAGreadXML.o

./DAGXMLParser.o : src/DAG/DAGXMLParser.cpp
	$(CC) $(CC_OPTIONS) src/DAG/DAGXMLParser.cpp -c $(INCLUDE) -o ./DAGXMLParser.o

./DependentVariable.o : src/DAG/DependentVariable.cpp
	$(CC) $(CC_OPTIONS) src/DAG/DependentVariable.cpp -c $(INCLUDE) -o ./DependentVariable.o

./Distribution.o : src/DAG/Distribution.cpp
	$(CC) $(CC_OPTIONS) src/DAG/Distribution.cpp -c $(INCLUDE) -o ./Distribution.o

./RandomVariable.o : src/DAG/RandomVariable.cpp
	$(CC) $(CC_OPTIONS) src/DAG/RandomVariable.cpp -c $(INCLUDE) -o ./RandomVariable.o

./Transformation.o : src/DAG/Transformation.cpp
	$(CC) $(CC_OPTIONS) src/DAG/Transformation.cpp -c $(INCLUDE) -o ./Transformation.o

./Variable.o : src/DAG/Variable.cpp
	$(CC) $(CC_OPTIONS) src/DAG/Variable.cpp -c $(INCLUDE) -o ./Variable.o

./Beta.o : src/Distributions/Beta.cpp
	$(CC) $(CC_OPTIONS) src/Distributions/Beta.cpp -c $(INCLUDE) -o ./Beta.o

./Binomial.o : src/Distributions/Binomial.cpp
	$(CC) $(CC_OPTIONS) src/Distributions/Binomial.cpp -c $(INCLUDE) -o ./Binomial.o

./ContinuousMixture.o : src/Distributions/ContinuousMixture.cpp
	$(CC) $(CC_OPTIONS) src/Distributions/ContinuousMixture.cpp -c $(INCLUDE) -o ./ContinuousMixture.o

./Distribution_ContinuousMosaic.o : src/Distributions/ContinuousMosaic.cpp
	$(CC) $(CC_OPTIONS) src/Distributions/ContinuousMosaic.cpp -c $(INCLUDE) -o ./Distribution_ContinuousMosaic.o

./Distribution_ContinuousMosaicBetaMixture.o : src/Distributions/ContinuousMosaicBetaMixture.cpp
	$(CC) $(CC_OPTIONS) src/Distributions/ContinuousMosaicBetaMixture.cpp -c $(INCLUDE) -o ./Distribution_ContinuousMosaicBetaMixture.o

./DistributionsXML.o : src/Distributions/DistributionsXML.cpp
	$(CC) $(CC_OPTIONS) src/Distributions/DistributionsXML.cpp -c $(INCLUDE) -o ./DistributionsXML.o

./Gamma.o : src/Distributions/Gamma.cpp
	$(CC) $(CC_OPTIONS) src/Distributions/Gamma.cpp -c $(INCLUDE) -o ./Gamma.o

./ImproperBeta.o : src/Distributions/ImproperBeta.cpp
	$(CC) $(CC_OPTIONS) src/Distributions/ImproperBeta.cpp -c $(INCLUDE) -o ./ImproperBeta.o

./ImproperLogUniform.o : src/Distributions/ImproperLogUniform.cpp
	$(CC) $(CC_OPTIONS) src/Distributions/ImproperLogUniform.cpp -c $(INCLUDE) -o ./ImproperLogUniform.o

./ImproperUniform.o : src/Distributions/ImproperUniform.cpp
	$(CC) $(CC_OPTIONS) src/Distributions/ImproperUniform.cpp -c $(INCLUDE) -o ./ImproperUniform.o

./InverseGamma.o : src/Distributions/InverseGamma.cpp
	$(CC) $(CC_OPTIONS) src/Distributions/InverseGamma.cpp -c $(INCLUDE) -o ./InverseGamma.o

./LogNormal.o : src/Distributions/LogNormal.cpp
	$(CC) $(CC_OPTIONS) src/Distributions/LogNormal.cpp -c $(INCLUDE) -o ./LogNormal.o

./LogUniform.o : src/Distributions/LogUniform.cpp
	$(CC) $(CC_OPTIONS) src/Distributions/LogUniform.cpp -c $(INCLUDE) -o ./LogUniform.o

./Normal.o : src/Distributions/Normal.cpp
	$(CC) $(CC_OPTIONS) src/Distributions/Normal.cpp -c $(INCLUDE) -o ./Normal.o

./Uniform.o : src/Distributions/Uniform.cpp
	$(CC) $(CC_OPTIONS) src/Distributions/Uniform.cpp -c $(INCLUDE) -o ./Uniform.o

./gcatLibrary.o : src/gcat/gcatLibrary.cpp
	$(CC) $(CC_OPTIONS) src/gcat/gcatLibrary.cpp -c $(INCLUDE) -o ./gcatLibrary.o

./gcatmain.o : src/gcat/gcatmain.cpp
	$(CC) $(CXXFLAGS) src/gcat/gcatmain.cpp -c $(INCLUDE) -o ./gcatmain.o

./ContinuousMosaicMoves.o : src/Inference/MCMC/ContinuousMosaicMoves.cpp
	$(CC) $(CC_OPTIONS) src/Inference/MCMC/ContinuousMosaicMoves.cpp -c $(INCLUDE) -o ./ContinuousMosaicMoves.o

./InferenceXML.o : src/Inference/InferenceXML.cpp
	$(CC) $(CC_OPTIONS) src/Inference/InferenceXML.cpp -c $(INCLUDE) -o ./InferenceXML.o

./MCMC.o : src/Inference/MCMC/MCMC.cpp
	$(CC) $(CC_OPTIONS) src/Inference/MCMC/MCMC.cpp -c $(INCLUDE) -o ./MCMC.o

./MPIMoves.o : src/Inference/MCMC/MPIMoves.cpp
	$(CC) $(CC_OPTIONS) src/Inference/MCMC/MPIMoves.cpp -c $(INCLUDE) -o ./MPIMoves.o

./PowellML.o : src/Inference/ML/PowellML.cpp
	$(CC) $(CC_OPTIONS) src/Inference/ML/PowellML.cpp -c $(INCLUDE) -o ./PowellML.o

./Continuous.o : src/RandomVariables/Continuous.cpp
	$(CC) $(CC_OPTIONS) src/RandomVariables/Continuous.cpp -c $(INCLUDE) -o ./Continuous.o

./RandomVariable_ContinuousMosaic.o : src/RandomVariables/ContinuousMosaic.cpp
	$(CC) $(CC_OPTIONS) src/RandomVariables/ContinuousMosaic.cpp -c $(INCLUDE) -o ./RandomVariable_ContinuousMosaic.o

./ContinuousVector.o : src/RandomVariables/ContinuousVector.cpp
	$(CC) $(CC_OPTIONS) src/RandomVariables/ContinuousVector.cpp -c $(INCLUDE) -o ./ContinuousVector.o

./Discrete.o : src/RandomVariables/Discrete.cpp
	$(CC) $(CC_OPTIONS) src/RandomVariables/Discrete.cpp -c $(INCLUDE) -o ./Discrete.o

./RandomVariablesXML.o : src/RandomVariables/RandomVariablesXML.cpp
	$(CC) $(CC_OPTIONS) src/RandomVariables/RandomVariablesXML.cpp -c $(INCLUDE) -o ./RandomVariablesXML.o

./AbsoluteTransform.o : src/Transformations/AbsoluteTransform.cpp
	$(CC) $(CC_OPTIONS) src/Transformations/AbsoluteTransform.cpp -c $(INCLUDE) -o ./AbsoluteTransform.o

./Concatenate.o : src/Transformations/Concatenate.cpp
	$(CC) $(CC_OPTIONS) src/Transformations/Concatenate.cpp -c $(INCLUDE) -o ./Concatenate.o

./ContinuousMosaicNumBlocks.o : src/Transformations/ContinuousMosaicNumBlocks.cpp
	$(CC) $(CC_OPTIONS) src/Transformations/ContinuousMosaicNumBlocks.cpp -c $(INCLUDE) -o ./ContinuousMosaicNumBlocks.o

./ContinuousVectorElement.o : src/Transformations/ContinuousVectorElement.cpp
	$(CC) $(CC_OPTIONS) src/Transformations/ContinuousVectorElement.cpp -c $(INCLUDE) -o ./ContinuousVectorElement.o

./ExponentialQuantileVector.o : src/Transformations/ExponentialQuantileVector.cpp
	$(CC) $(CC_OPTIONS) src/Transformations/ExponentialQuantileVector.cpp -c $(INCLUDE) -o ./ExponentialQuantileVector.o

./ExponentialTransform.o : src/Transformations/ExponentialTransform.cpp
	$(CC) $(CC_OPTIONS) src/Transformations/ExponentialTransform.cpp -c $(INCLUDE) -o ./ExponentialTransform.o

./FractionTransform.o : src/Transformations/FractionTransform.cpp
	$(CC) $(CC_OPTIONS) src/Transformations/FractionTransform.cpp -c $(INCLUDE) -o ./FractionTransform.o

./InverseLogitTransform.o : src/Transformations/InverseLogitTransform.cpp
	$(CC) $(CC_OPTIONS) src/Transformations/InverseLogitTransform.cpp -c $(INCLUDE) -o ./InverseLogitTransform.o

./LinearMosaic.o : src/Transformations/LinearMosaic.cpp
	$(CC) $(CC_OPTIONS) src/Transformations/LinearMosaic.cpp -c $(INCLUDE) -o ./LinearMosaic.o

./LogLikelihoodTransform.o : src/Transformations/LogLikelihoodTransform.cpp
	$(CC) $(CC_OPTIONS) src/Transformations/LogLikelihoodTransform.cpp -c $(INCLUDE) -o ./LogLikelihoodTransform.o

./PowerTransform.o : src/Transformations/PowerTransform.cpp
	$(CC) $(CC_OPTIONS) src/Transformations/PowerTransform.cpp -c $(INCLUDE) -o ./PowerTransform.o

./ProductTransform.o : src/Transformations/ProductTransform.cpp
	$(CC) $(CC_OPTIONS) src/Transformations/ProductTransform.cpp -c $(INCLUDE) -o ./ProductTransform.o

./SumTransform.o : src/Transformations/SumTransform.cpp
	$(CC) $(CC_OPTIONS) src/Transformations/SumTransform.cpp -c $(INCLUDE) -o ./SumTransform.o

./TransformationsXML.o : src/Transformations/TransformationsXML.cpp
	$(CC) $(CC_OPTIONS) src/Transformations/TransformationsXML.cpp -c $(INCLUDE) -o ./TransformationsXML.o


#
# Build the parts of gammaMap
#

./Codon61Count.o : src/gammaMap/RandomVariables/Codon61Count.cpp
	$(CC) $(CC_OPTIONS) src/gammaMap/RandomVariables/Codon61Count.cpp -c $(INCLUDE) -o ./Codon61Count.o

./Codon61Sequence.o : src/gammaMap/RandomVariables/Codon61Sequence.cpp
	$(CC) $(CC_OPTIONS) src/gammaMap/RandomVariables/Codon61Sequence.cpp -c $(INCLUDE) -o ./Codon61Sequence.o

./Codon61SequenceStationaryDistribution.o : src/gammaMap/Distributions/Codon61SequenceStationaryDistribution.cpp
	$(CC) $(CC_OPTIONS) src/gammaMap/Distributions/Codon61SequenceStationaryDistribution.cpp -c $(INCLUDE) -o ./Codon61SequenceStationaryDistribution.o

./gammaMapHMMHybrid.o : src/gammaMap/Distributions/gammaMapHMMHybrid.cpp
	$(CC) $(CC_OPTIONS) src/gammaMap/Distributions/gammaMapHMMHybrid.cpp -c $(INCLUDE) -o ./gammaMapHMMHybrid.o

./gammaMapLibrary.o : src/gammaMap/gammaMapLibrary.cpp
	$(CC) $(CC_OPTIONS) src/gammaMap/gammaMapLibrary.cpp -c $(INCLUDE) -o ./gammaMapLibrary.o

./gammaMapMain.o : src/gammaMap/gammaMapMain.cpp
	$(CC) $(CC_OPTIONS) src/gammaMap/gammaMapMain.cpp -c $(INCLUDE) -o ./gammaMapMain.o

./gammaMapMoves.o : src/gammaMap/Inference/MCMC/gammaMapMoves.cpp
	$(CC) $(CC_OPTIONS) src/gammaMap/Inference/MCMC/gammaMapMoves.cpp -c $(INCLUDE) -o ./gammaMapMoves.o

./gammaMapUtils.o : src/gammaMap/Utilities/gammaMapUtils.cpp
	$(CC) $(CC_OPTIONS) src/gammaMap/Utilities/gammaMapUtils.cpp -c $(INCLUDE) -o ./gammaMapUtils.o

./gammaMapXML.o : src/gammaMap/gammaMapXML.cpp
	$(CC) $(CC_OPTIONS) src/gammaMap/gammaMapXML.cpp -c $(INCLUDE) -o ./gammaMapXML.o

./mutation.o : src/gammaMap/Utilities/mutation.cpp
	$(CC) $(CC_OPTIONS) src/gammaMap/Utilities/mutation.cpp -c $(INCLUDE) -o ./mutation.o

./paml.o : src/gammaMap/Utilities/paml.c
	$(CC) $(CC_OPTIONS) src/gammaMap/Utilities/paml.c -c $(INCLUDE) -o ./paml.o

##### END RUN ####
