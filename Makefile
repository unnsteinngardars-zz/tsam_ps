CC = gcc
CXX = g++
CXXFLAGS = -g -Wall --std=c++11

SYN = syn-scan.cpp
CONNECT = connect-scan.cpp

syn: $(SYN)
	$(CXX) $(CXXFLAGS) -o syn-scan $(SYN)
connect: $(CONNECT)
	$(CXX) $(CXXFLAGS) -o connect-scan $(CONNECT)



# utilities: $(UTILITIES)
# 	$(CXX) $(CXXFLAGS) -o $(UTILITIES)



# connect-scan: connect-scan.cpp
# 	g++ --std=c++11 -o connect-scan connect-scan.cpp
# syn-scan: syn-scan.cpp
# 	g++ --std=c++11 -o syn-scan syn-scan.cpp -lpthread 
