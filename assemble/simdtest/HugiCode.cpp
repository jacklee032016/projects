#include "Matrix4f.h"
#include "Vector4f.h"

// MatrixMultiply1 -- a naive C++ matrix-vector multiplication function.
// It's correct, but that's about the only thing impressive about it.
//
// Performance: ~90 cycles/vector
Vector4f MatrixMultiply1(Matrix4f &m, Vector4f &vin)
{
	float v0 =	m.elts[0][0]*vin[0] + m.elts[0][1]*vin[1] + 
							m.elts[0][2]*vin[2] + m.elts[0][3]*vin[3];
	float v1 =  m.elts[1][0]*vin[0] + m.elts[1][1]*vin[1] +
							m.elts[1][2]*vin[2] + m.elts[1][3]*vin[3];
	float v2 =  m.elts[2][0]*vin[0] + m.elts[2][1]*vin[1] +
							m.elts[2][2]*vin[2] + m.elts[2][3]*vin[3];
	float v3 =  m.elts[3][0]*vin[0] + m.elts[3][1]*vin[1] + 
							m.elts[3][2]*vin[2] + m.elts[3][3]*vin[3];
	return Vector4f(v0,v1,v2,v3);
}



// MatrixMultiply2 -- a faster version of MatrixMultiply1, still in C++.
//
// Performance: 70 cycles/vector
void MatrixMultiply2(Matrix4f &m, Vector4f *vin, Vector4f *vout)
{
	float *in = vin->Ref();
	float *out = vout->Ref();
	out[0] =	m.elts[0][0]*in[0] + m.elts[0][1]*in[1] + 
						m.elts[0][2]*in[2] + m.elts[0][3]*in[3];
	out[1] =  m.elts[1][0]*in[0] + m.elts[1][1]*in[1] +
						m.elts[1][2]*in[2] + m.elts[1][3]*in[3];
	out[2] =  m.elts[2][0]*in[0] + m.elts[2][1]*in[1] +
						m.elts[2][2]*in[2] + m.elts[2][3]*in[3];
	out[3] =  m.elts[3][0]*in[0] + m.elts[3][1]*in[1] + 
						m.elts[3][2]*in[2] + m.elts[3][3]*in[3];
}



// MatrixMultiply3 -- a C++/ASM version of MatrixMultiply2, which takes
// advantage of Intel's SSE instructions.  This version requires that
// M be in column-major order.
//
// Performance: 57 cycles/vector
void MatrixMultiply3(Matrix4f &m, Vector4f *vin, Vector4f *vout)
{
	// Get a pointer to the elements of m
	float *row0 = m.Ref();

	__asm {
		mov			esi, vin
		mov			edi, vout

		// load columns of matrix into xmm4-7
		mov			edx, row0
		movups	xmm4, [edx]
		movups	xmm5, [edx+0x10]
		movups	xmm6, [edx+0x20]
		movups	xmm7, [edx+0x30]

		// load v into xmm0.
		movups	xmm0, [esi]

		// we'll store the final result in xmm2; initialize it
		// to zero
		xorps		xmm2, xmm2

		// broadcast x into xmm1, multiply it by the first
		// column of the matrix (xmm4), and add it to the total
		movups	xmm1, xmm0
		shufps	xmm1, xmm1, 0x00
		mulps		xmm1, xmm4
		addps		xmm2, xmm1

		// repeat the process for y, z and w
		movups	xmm1, xmm0
		shufps	xmm1, xmm1, 0x55
		mulps		xmm1, xmm5
		addps		xmm2, xmm1
		movups	xmm1, xmm0
		shufps	xmm1, xmm1, 0xAA
		mulps		xmm1, xmm6
		addps		xmm2, xmm1
		movups	xmm1, xmm0
		shufps	xmm1, xmm1, 0xFF
		mulps		xmm1, xmm7
		addps		xmm2, xmm1

		// write the results to vout
		movups	[edi], xmm2
	}
}


// BatchMultiply1 -- A modification to MatrixMultiply2 in which we
// multiply several input vectors (vin) by the same matrix (m), storing the
// results in 'vout'.  A total of 'len' vectors are processed.  This
// prevents us from having to re-load 'm' every time through the loop.
// This also allows us to embed the tranpose operation into the function
// body, so we can continue to store our matrices in row-major order,
// if we wish.
//
// Performance: 32 cycles/vector
void BatchMultiply1(Matrix4f &m, Vector4f *vin, Vector4f *vout, int len)
{
	// transpose the matrix into the xmm4-7
	m.TransposeIntoXMM();
	static const int vecSize = sizeof(Vector4f);

	__asm {
		mov			esi, vin
		mov			edi, vout
		mov			ecx, len

BM1_START:
		// load the next input vector into xmm0, and advance the input
		// pointer
		movups	xmm0, [esi]
		add			esi, vecSize

		// we'll store the final result in xmm2; initialize it
		// to zero
		xorps		xmm2, xmm2

		// broadcast x into xmm1, multiply it by the first
		// column of the matrix (xmm4), and add it to the total
		movups	xmm1, xmm0
		shufps	xmm1, xmm1, 0x00
		mulps		xmm1, xmm4
		addps		xmm2, xmm1

		// repeat the process for y, z and w
		movups	xmm1, xmm0
		shufps	xmm1, xmm1, 0x55
		mulps		xmm1, xmm5
		addps		xmm2, xmm1
		movups	xmm1, xmm0
		shufps	xmm1, xmm1, 0xAA
		mulps		xmm1, xmm6
		addps		xmm2, xmm1
		movups	xmm1, xmm0
		shufps	xmm1, xmm1, 0xFF
		mulps		xmm1, xmm7
		addps		xmm2, xmm1

		// write the results to vout, and advance the output pointer
		movups	[edi], xmm2
		add			edi, vecSize
		dec			ecx
		jnz			BM1_START
	}
}



// BatchMultiply2 -- A simple modification to BatchMultiply1: we now use
// aligned moves (movaps) instead of unaligned moves (movups).  This is much
// faster, but requires that Matrix4f and Vector4f objects are aligned
// on 16-byte boundaries.  We use the __declspec(align(16)) specifier in
// the Matrix4f and Vector4f class definitions to accomplish this.
//
// Performance: 28 cycles/vector
void BatchMultiply2(Matrix4f &m, Vector4f *vin, Vector4f *vout, int len)
{
	// transpose the matrix into the xmm4-7
	m.TransposeIntoXMM();
	static const int vecSize = sizeof(Vector4f);

	__asm {
		mov			esi, vin
		mov			edi, vout
		mov			ecx, len

BM2_START:
		// load the next input vector into xmm0, and advance the input
		// pointer
		movaps	xmm0, [esi]
		add			esi, vecSize

		// we'll store the final result in xmm2; initialize it
		// to zero
		xorps		xmm2, xmm2

		// broadcast x into xmm1, multiply it by the first
		// column of the matrix (xmm4), and add it to the total
		movaps	xmm1, xmm0
		shufps	xmm1, xmm1, 0x00
		mulps		xmm1, xmm4
		addps		xmm2, xmm1

		// repeat the process for y, z and w
		movaps	xmm1, xmm0
		shufps	xmm1, xmm1, 0x55
		mulps		xmm1, xmm5
		addps		xmm2, xmm1
		movaps	xmm1, xmm0
		shufps	xmm1, xmm1, 0xAA
		mulps		xmm1, xmm6
		addps		xmm2, xmm1
		movaps	xmm1, xmm0
		shufps	xmm1, xmm1, 0xFF
		mulps		xmm1, xmm7
		addps		xmm2, xmm1

		// write the results to vout, advance the output pointer,
		// and loop
		movaps	[edi], xmm2
		add			edi, vecSize
		dec			ecx
		jnz			BM2_START
	}
}


// BatchMultiply3 -- A modification to BatchMultiply2 which makes better
// use of instruction pairing.
//
// Performance: 22 cycles/vector
void BatchMultiply3(Matrix4f &m, Vector4f *vin, Vector4f *vout, int len)
{
	// transpose the matrix into the xmm4-7
	m.TransposeIntoXMM();
	static const int vecSize = sizeof(Vector4f);

	__asm {
		mov			esi, vin
		mov			edi, vout
		mov			ecx, len

BM3_START:
		// load the next input vector into xmm0, and advance the input
		// and output pointers
		movaps	xmm0, [esi]
		add			edi, vecSize

		// broadcast y into xmm1, z into xmm2, and w into xmm3 (leaving
		// x in xmm0).
		movaps	xmm1, xmm0
		add			esi, vecSize
		movaps	xmm2, xmm0
		movaps	xmm3, xmm0
		shufps	xmm0, xmm0, 0x00
		shufps	xmm1, xmm1, 0x55
		shufps	xmm2, xmm2, 0xAA
		shufps	xmm3, xmm3, 0xFF
		
		// multiply xmm0-3 by the appropriate columns of the matrix
		mulps		xmm0, xmm4
		mulps		xmm1, xmm5
		mulps		xmm2, xmm6
		mulps		xmm3, xmm7

		// sum the results into xmm1
		addps		xmm1, xmm0
		addps		xmm2, xmm3
		addps		xmm1, xmm2

		// write the results to vout, and loop
		movaps	[edi-0x10], xmm1
		dec			ecx
		jnz			BM3_START
	}
}

// BatchMultiply4 -- A modification to BatchMultiply3 which uses 
// SSE prefetching instructions to improve performance with large
// input sets.
//
// Performance: 21 cycles/vector
void BatchMultiply4(Matrix4f &m, Vector4f *vin, Vector4f *vout, int len)
{
	// transpose the matrix into the xmm4-7
	m.TransposeIntoXMM();
	static const int vecSize = sizeof(Vector4f);

	__asm {
		mov			esi, vin
		mov			edi, vout
		mov			ecx, len

BM4_START:
		// load the next input vector into xmm0, and advance the input
		// pointer.  Prefetch upcoming vectors into the cache
		movaps	xmm0, [esi]
		prefetchnta	[esi+0x30]

		// broadcast y into xmm1, z into xmm2, and w into xmm3 (leaving
		// x in xmm0).
		movaps	xmm1, xmm0
		add			esi, vecSize
		movaps	xmm2, xmm0
		add			edi, vecSize
		movaps	xmm3, xmm0
		prefetchnta [edi+0x30]
		shufps	xmm0, xmm0, 0x00
		shufps	xmm1, xmm1, 0x55
		shufps	xmm2, xmm2, 0xAA
		shufps	xmm3, xmm3, 0xFF
		
		// multiply xmm0-3 by the appropriate columns of the matrix
		// (hiding a pointer increment between the multiplies)
		mulps		xmm0, xmm4
		mulps		xmm1, xmm5
		mulps		xmm2, xmm6
		mulps		xmm3, xmm7

		// sum the results into xmm1
		addps		xmm1, xmm0
		addps		xmm2, xmm3
		addps		xmm1, xmm2

		// write the results to vout, and loop
		movaps	[edi-0x10], xmm1
		dec			ecx
		jnz			BM4_START
	}
}


// BatchMultiply5 -- A modified version of BatchMultiply4 which loads
// vector components individually from memory, thereby allowing us
// to work on TWO VECTORS SIMULTANEOUSLY!
//
// Performance: 20 cycles/vector
void BatchMultiply5(Matrix4f &m, Vector4f *vin, Vector4f *vout, int len)
{
	// initializations in C++ land
	Matrix4f mt(m, Matrix4f::TRANSPOSE); // work from a 
	float *row0 = mt.Ref();
	static const int vecSize = 2 * sizeof(Vector4f);
	
	// if there are an odd number of vectors, process the first one
	// separately and advance the pointers
	if (len & 0x1) {
		MatrixMultiply3(mt, vin, vout);
		++vin;
		++vout;
	}
	len >>= 1; // we process two vectors at a time

	__asm {
		mov			esi, vin
		mov			edi, vout
		mov			ecx, len

		// load columns of matrix into xmm4-7
		mov			edx, row0
		movaps	xmm4, [edx]
		movaps	xmm5, [edx+0x10]
		movaps	xmm6, [edx+0x20]
		movaps	xmm7, [edx+0x30]

BM5_START:
		
		// process x
		movss		xmm1, [esi+0x00]
		movss		xmm3, [esi+0x10]
		shufps	xmm1, xmm1, 0x00
		prefetchnta	[esi+0x30]
		shufps	xmm3, xmm3, 0x00
		mulps		xmm1, xmm4
		prefetchnta [edi+0x30]
		mulps		xmm3, xmm4

		// process y
		movss		xmm0, [esi+0x04]
		movss		xmm2, [esi+0x14]
		shufps	xmm0, xmm0, 0x00
		shufps	xmm2, xmm2, 0x00
		mulps		xmm0, xmm5
		mulps		xmm2, xmm5
		addps		xmm1, xmm0
		addps		xmm3, xmm2

		// process z
		movss		xmm0, [esi+0x08]
		movss		xmm2, [esi+0x18]
		shufps	xmm0, xmm0, 0x00
		shufps	xmm2, xmm2, 0x00
		mulps		xmm0, xmm6
		mulps		xmm2, xmm6
		addps		xmm1, xmm0
		addps		xmm3, xmm2

		// process w (hiding some pointer increments between the
		// multiplies)
		movss		xmm0, [esi+0x0C]
		movss		xmm2, [esi+0x1C]
		shufps	xmm0, xmm0, 0x00
		shufps	xmm2, xmm2, 0x00
		mulps		xmm0, xmm7
		add			esi, vecSize
		mulps		xmm2, xmm7
		add			edi, vecSize
		addps		xmm1, xmm0
		addps		xmm3, xmm2

		// write output vectors to memory, and loop
		movaps	[edi-0x20], xmm1
		movaps	[edi-0x10], xmm3
		dec			ecx
		jnz			BM5_START
	}
}



// BatchTransform1 -- A modified version of BatchMultiply4 which makes
// an additional assumption about the vectors in vin: if each vector's
// 4th element (the homogenous coordinate w) is assumed to be 1.0 (as is
// the case for 3D vertices), we can eliminate a move, a shuffle and a
// multiply instruction.
//
// Performance: 17 cycles/vector
void BatchTransform1(Matrix4f &m, Vector4f *vin, Vector4f *vout, int len)
{
	// initializations in C++ land
	Matrix4f mt(m, Matrix4f::TRANSPOSE); // work from a 
	float *row0 = mt.Ref();
	static const int vecSize = 2 * sizeof(Vector4f);
	
	// if there are an odd number of vectors, process the first one
	// separately and advance the pointers
	if (len & 0x1) {
		MatrixMultiply3(mt, vin, vout);
		++vin;
		++vout;
	}
	len >>= 1; // we process two vectors at a time

	__asm {
		mov		esi, vin
		mov		edi, vout
		mov		ecx, len

		// load columns of matrix into xmm4-7
		mov		edx, row0
		movaps	xmm4, [edx]
		movaps	xmm5, [edx+0x10]
		movaps	xmm6, [edx+0x20]
		movaps	xmm7, [edx+0x30]

BT2_START:
		// process x (hiding the prefetches in the delays)
		movss		xmm1, [esi+0x00]
		movss		xmm3, [esi+0x10]
		shufps	xmm1, xmm1, 0x00
		prefetchnta [edi+0x30]
		shufps	xmm3, xmm3, 0x00
		mulps		xmm1, xmm4
		prefetchnta	[esi+0x30]
		mulps		xmm3, xmm4

		// process y
		movss		xmm0, [esi+0x04]
		movss		xmm2, [esi+0x14]
		shufps	xmm0, xmm0, 0x00
		shufps	xmm2, xmm2, 0x00
		mulps		xmm0, xmm5
		mulps		xmm2, xmm5
		addps		xmm1, xmm0
		addps		xmm3, xmm2

		// process z (hiding some pointer arithmetic between
		// the multiplies)
		movss		xmm0, [esi+0x08]
		movss		xmm2, [esi+0x18]
		shufps	xmm0, xmm0, 0x00
		shufps	xmm2, xmm2, 0x00
		mulps		xmm0, xmm6
		add			esi, vecSize
		mulps		xmm2, xmm6
		add			edi, vecSize
		addps		xmm1, xmm0
		addps		xmm3, xmm2

		// process w
		addps		xmm1, xmm7
		addps		xmm3, xmm7

		// write output vectors to memory and loop
		movaps	[edi-0x20], xmm1
		movaps	[edi-0x10], xmm3
		dec			ecx
		jnz			BT2_START
	}
}