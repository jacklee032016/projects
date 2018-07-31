// Matrix4f.cpp: implementation of the Matrix4f class.
//
//////////////////////////////////////////////////////////////////////

#include "Matrix4f.h"
#include "Vector4f.h"
#include "string.h"
#include <iostream>
#include <cassert>
//#include "timer.h"
#include <algorithm>

using namespace std;

const bool Matrix4f::TRANSPOSE = true;

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
Matrix4f::Matrix4f( float m00, float m01, float m02, float m03,
										float m10, float m11, float m12, float m13,
										float m20, float m21, float m22, float m23,
										float m30, float m31, float m32, float m33)
{
	elts[0][0] = m00; elts[0][1] = m01; elts[0][2] = m02; elts[0][3] = m03;
	elts[1][0] = m10; elts[1][1] = m11; elts[1][2] = m12; elts[1][3] = m13;
	elts[2][0] = m20; elts[2][1] = m21; elts[2][2] = m22; elts[2][3] = m23;
	elts[3][0] = m30; elts[3][1] = m31; elts[3][2] = m32; elts[3][3] = m33;
}

Matrix4f::Matrix4f(const Matrix4f &rhs, bool transpose)
{
	if (transpose) {
		this->elts[0][0] = rhs.elts[0][0];
		this->elts[0][1] = rhs.elts[1][0];
		this->elts[0][2] = rhs.elts[2][0];
		this->elts[0][3] = rhs.elts[3][0];
		this->elts[1][0] = rhs.elts[0][1];
		this->elts[1][1] = rhs.elts[1][1];
		this->elts[1][2] = rhs.elts[2][1];
		this->elts[1][3] = rhs.elts[3][1];
		this->elts[2][0] = rhs.elts[0][2];
		this->elts[2][1] = rhs.elts[1][2];
		this->elts[2][2] = rhs.elts[2][2];
		this->elts[2][3] = rhs.elts[3][2];
		this->elts[3][0] = rhs.elts[0][3];
		this->elts[3][1] = rhs.elts[1][3];
		this->elts[3][2] = rhs.elts[2][3];
		this->elts[3][3] = rhs.elts[3][3];
	} else {
		memcpy(this->elts, rhs.elts, 16*sizeof(float));
	}
}

Matrix4f::~Matrix4f()
{

}


///////////////////////////////////////////////////////////////////////////
// output functions
///////////////////////////////////////////////////////////////////////////
void Matrix4f::print(ostream &out) const
{
	out << "[" << elts[0][0] << ", " << elts[0][1] << ", "
		<< elts[0][2] << ", " << elts[0][3] << "]" << endl;
	out << "[" << elts[1][0] << ", " << elts[1][1] << ", "
		<< elts[1][2] << ", " << elts[1][3] << "]" << endl;
	out << "[" << elts[2][0] << ", " << elts[2][1] << ", "
		<< elts[2][2] << ", " << elts[2][3] << "]" << endl;
	out << "[" << elts[3][0] << ", " << elts[3][1] << ", "
		<< elts[3][2] << ", " << elts[3][3] << "]" << endl;
}
ostream& operator<<(ostream &out, const Matrix4f &m)
{
	m.print(out);
	return out;
}



///////////////////////////////////////////////////////////////////////////
// arithmetic operations
///////////////////////////////////////////////////////////////////////////
Vector4f Matrix4f::operator*(const Vector4f &v)
{
	float v0 = elts[0][0]*v[0]+elts[0][1]*v[1]+elts[0][2]*v[2]+elts[0][3]*v[3];
	float v1 = elts[1][0]*v[0]+elts[1][1]*v[1]+elts[1][2]*v[2]+elts[1][3]*v[3];
	float v2 = elts[2][0]*v[0]+elts[2][1]*v[1]+elts[2][2]*v[2]+elts[2][3]*v[3];
	float v3 = elts[3][0]*v[0]+elts[3][1]*v[1]+elts[3][2]*v[2]+elts[3][3]*v[3];
	Vector4f copy(v0, v1, v2, v3);
	return copy;
}



///////////////////////////////////////////////////////////////////////////
// other operations functions
///////////////////////////////////////////////////////////////////////////
void Matrix4f::Transpose(void)
{
	std::swap(elts[0][1], elts[1][0]);
	std::swap(elts[0][2], elts[2][0]);
	std::swap(elts[0][3], elts[3][0]);
	std::swap(elts[1][2], elts[2][1]);
	std::swap(elts[1][3], elts[3][1]);
	std::swap(elts[2][3], elts[3][2]);
}

void Matrix4f::TransposeIntoXMM(void)
{
	float *tempElts = this->Ref();
	__asm {
		mov			ebx, tempElts
		movlps	xmm4, [ebx]		   // load x and y of r0 to low xmm4
		movhps 	xmm4, [ebx+0x10] // load x and y of r1 to high xmm4
		movlps 	xmm3, [ebx+0x20] // load x and y of r2 to low xmm3
		movhps 	xmm3, [ebx+0x30] // load x and y of r3 to high xmm3
		movaps 	xmm5, xmm4		
		shufps 	xmm4, xmm3, 0x88 // create x (extract x-values)
		shufps 	xmm5, xmm3, 0xDD // create y (extract y-values)

		movlps 	xmm6, [ebx+0x08] // load z and w of r0 to low xmm6
		movhps 	xmm6, [ebx+0x18] // load z and w of r1 to high xmm6
		movlps 	xmm3, [ebx+0x28] // load z and w of r2 to low xmm3
		movhps 	xmm3, [ebx+0x38] // load z and w of r3 to high xmm3
		movaps	xmm7,	xmm6		
		shufps 	xmm6, xmm3, 0x88 // create z (extract z-values)
		shufps	xmm7,	xmm3,	0xDD // create w (extract w-values)
	}
}