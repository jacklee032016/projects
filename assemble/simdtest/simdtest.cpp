#include <iostream>
#include <cstdlib>
#include "Vector4f.h"
#include "Matrix4f.h"
#include "HugiCode.h"
#include "timer.h"
#include <cassert>
#include <cmath>

using namespace std;

// how many vectors to run through each version?
#define VECLEN 1000

///////////////////////////// FlushCache
// flushes the entire cache before each test, to demonstrate
// the advantage of the prefetch instruction
#define L2_CACHE_SIZE 524288 // 512K
static bool FLUSH_CACHE = false; // should we flush or not?
static unsigned char CacheArray[L2_CACHE_SIZE];

void FlushCache()
{
	if (FLUSH_CACHE)
		memset( CacheArray, 0, L2_CACHE_SIZE);
}



///////////////////////////// VerifyAccuracy
// makes sure that m * vin[i] = vout[i] for all i
bool VerifyAccuracy(Matrix4f &m, Vector4f *vin, Vector4f *vout)
{
	int i = VECLEN;
	bool isAccurate = true;
	Vector4f testTarget;

	while(i--) {
		testTarget = m * vin[i];
		if ( !(vout[i] == testTarget) ) {
			cout << "MULTIPLICATION ERROR in vout[" << i << "]: "
					<< vout[i] << " != " << testTarget << endl;
			isAccurate = false;
		}
	}

	return isAccurate;
}

///////////////////////////// Usage
void usage(void)
{
	cerr << "Usage: simdtest [-f]\n";
	//cerr << "-v NUMVECTORS:  set the number of vectors to test [1000]\n";
	cerr << "-f:             flushes the cache before each test  [no]\n";
}

///////////////////////////// Main
int main(int argc, char *argv[])
{
	// read command line arguments
	if (argc > 2) {
		usage();
		exit(0);
	}
	for(int a=1; a<argc; ++a) {
		if (strcmp(argv[a], "--help") == 0 || strcmp(argv[a], "-h") == 0) {
			usage();
			exit(0);
		} else if (strcmp(argv[a], "-f") == 0) {
			FLUSH_CACHE = true;
		}
	}

	Matrix4f m( 2, 0, 0, 1,
							0, 2, 0, 1,
							0, 0, 2, 1,
							0, 0, 0, 2);
	Matrix4f mt(m, Matrix4f::TRANSPOSE);

	///////////// test matrix multiplication
	int i, start, end;
	Vector4f testIn[VECLEN];
	Vector4f testOut[VECLEN];

	// time the timing function overhead; we subtract this from all other measurements
	start = GetPentiumTimer();
	end = GetPentiumTimer();
	int timerOverhead = end - start;
	cout << "timer overhead: " << timerOverhead << endl;

	// initialize vector streams
	for(i=0; i<VECLEN; ++i)
		testIn[i] = Vector4f(rand(),rand(),rand(),rand());

	cout << "Each test is run on " << VECLEN << " vectors\n\n";

	// test MatrixMultiply1
	i=VECLEN;
	FlushCache();
	start = GetPentiumTimer();
	for(i=0; i<VECLEN; ++i)
		testOut[i] = MatrixMultiply1(m, testIn[i]);
	end = GetPentiumTimer();
	cout << "MatrixMultiply1 (naive C++):            "
		<< ((end-start-timerOverhead) / VECLEN) << " cycles/vec\n";
	VerifyAccuracy(m, testIn, testOut);

	// test MatrixMultiply2
	i=VECLEN;
	FlushCache();
	start = GetPentiumTimer();
	while(i--)
		MatrixMultiply2(m, testIn+i, testOut+i);
	end = GetPentiumTimer();
	cout << "MatrixMultiply2 (faster C++):           "
		<< ((end-start-timerOverhead) / VECLEN) << " cycles/vec\n";
	VerifyAccuracy(m, testIn, testOut);

	// test MatrixMultiply3 -- we must use mt, the transposed version
	// of m
	i=VECLEN;
	FlushCache();
	start = GetPentiumTimer();
	while(i--)
		MatrixMultiply3(mt, testIn+i, testOut+i);
	end = GetPentiumTimer();
	cout << "MatrixMultiply3 (C++/ASM/SSE):          "
		<< ((end-start-timerOverhead) / VECLEN) << " cycles/vec\n";
	VerifyAccuracy(m, testIn, testOut);

	// test BatchMultiply1
	FlushCache();
	start = GetPentiumTimer();
	BatchMultiply1(m, testIn, testOut, VECLEN);
	end = GetPentiumTimer();
	cout << "BatchMultiply1  (+batch processing):    "
		<< ((end-start-timerOverhead) / VECLEN) << " cycles/vec\n";
	VerifyAccuracy(m, testIn, testOut);

	// test BatchMultiply2
	FlushCache();
	start = GetPentiumTimer();
	BatchMultiply2(m, testIn, testOut, VECLEN);
	end = GetPentiumTimer();
	cout << "BatchMultiply2  (+aligned moves):       "
		<< ((end-start-timerOverhead) / VECLEN) << " cycles/vec\n";
	VerifyAccuracy(m, testIn, testOut);

	// test BatchMultiply3
	FlushCache();
	start = GetPentiumTimer();
	BatchMultiply3(m, testIn, testOut, VECLEN);
	end = GetPentiumTimer();
	cout << "BatchMultiply3  (+instruction pairing): "
		<< ((end-start-timerOverhead) / VECLEN) << " cycles/vec\n";
	VerifyAccuracy(m, testIn, testOut);

	// test BatchMultiply4
	FlushCache();
	start = GetPentiumTimer();
	BatchMultiply4(m, testIn, testOut, VECLEN);
	end = GetPentiumTimer();
	cout << "BatchMultiply4  (+prefetching):         "
		<< ((end-start-timerOverhead) / VECLEN) << " cycles/vec\n";
	VerifyAccuracy(m, testIn, testOut);

	// test BatchMultiply5
	FlushCache();
	start = GetPentiumTimer();
	BatchMultiply5(m, testIn, testOut, VECLEN);
	end = GetPentiumTimer();
	cout << "BatchMultiply5  (+movss):               "
		<< ((end-start-timerOverhead) / VECLEN) << " cycles/vec\n";
	VerifyAccuracy(m, testIn, testOut);

	// test BatchTransform1 -- testIn must be reinitialized
	for(i=0; i<VECLEN; ++i)
		testIn[i] = Vector4f(rand(), rand(), rand(), 1.0);
	FlushCache();
	start = GetPentiumTimer();
	BatchTransform1(m, testIn, testOut, VECLEN);
	end = GetPentiumTimer();
	cout << "BatchTransform1 (+w equals 1.0):        "
		<< ((end-start-timerOverhead) / VECLEN) << " cycles/vec\n";
	VerifyAccuracy(m, testIn, testOut);

	return 0;
}