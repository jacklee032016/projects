// Matrix4f.h: interface for the Matrix4f class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_MATRIX4F_H__333CD0CF_D46E_4094_866B_10D4C504E498__INCLUDED_)
#define AFX_MATRIX4F_H__333CD0CF_D46E_4094_866B_10D4C504E498__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <iostream>
#include "Vector4f.h"

using namespace std;

class Matrix4f  
{
private:
	__declspec(align(16)) float elts[4][4];
	void print(ostream &out) const;
public:
	// construction and destruction
	Matrix4f() {}
	Matrix4f( float m00, float m01, float m02, float m03,
						float m10, float m11, float m12, float m13,
						float m20, float m21, float m22, float m23,
						float m30, float m31, float m32, float m33);
	Matrix4f(const Matrix4f &rhs, bool transpose=false);
	virtual ~Matrix4f();

	// access functions
	float *Ref(void) { return reinterpret_cast<float*>(elts); }
	float *Row(int r) { return elts[r]; }

	// output functions
	friend ostream& operator <<(ostream &out, const Matrix4f &m);

	// arithmetic operations
	Vector4f operator*(const Vector4f &v);

	// other operations
	void Transpose(void); // transpose in-place
	void TransposeIntoXMM(void); // transpose matrix into the xmm registers
	static const bool TRANSPOSE;

	friend Vector4f MatrixMultiply1(Matrix4f &m, Vector4f &vin);
	friend void MatrixMultiply2(Matrix4f &m, Vector4f *vin, Vector4f *vout);
};

#endif // !defined(AFX_MATRIX4F_H__333CD0CF_D46E_4094_866B_10D4C504E498__INCLUDED_)
