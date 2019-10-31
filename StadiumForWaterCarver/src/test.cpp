#include "Utils.h"
#include <iostream>
#include <thread>
#include <chrono>
#include "WaterCarver.h"

static int kNumTests = 1;

int main()
{
	time_t begin = time(NULL);
	//test();
	watercarver();
	//testPoint();
	std::cout << "stress test is done in " << time(NULL) - begin << " seconds" << std::endl;

	return 0;
}
