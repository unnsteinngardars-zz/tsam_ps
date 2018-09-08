CC = gcc
CXX = g++
CXXFLAGS = -g -Wall --std=c++11

SCAN = scan.cpp syn.cpp scan_utilities.cpp
CONNECT = connect-scan.cpp

scan: $(SCAN)
	$(CXX) $(CXXFLAGS) -o scan $(SCAN) -lpthread
connect: $(CONNECT)
	$(CXX) $(CXXFLAGS) -o connect-scan $(CONNECT)