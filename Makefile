connect-scan: connect-scan.cpp
	g++ --std=c++11 -o connect-scan connect-scan.cpp
syn-scan: syn-scan.cpp
	g++ --std=c++11 -o syn-scan syn-scan.cpp -lpthread 