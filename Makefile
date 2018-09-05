tcpc: tcpc.cpp
	g++ --std=c++11 -o tcpc tcpc.cpp
syn: syn.cpp
	g++ --std=c++11 -o syn syn.cpp -lpthread 