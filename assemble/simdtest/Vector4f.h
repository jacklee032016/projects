#ifndef __VECTOR4F_H__
#define __VECTOR4F_H__

#include <iostream>

using namespace std;

//////////////////////////// Vector class
__declspec( align(16) ) class Vector4f
{
private:
	float elts[4];
	void print(ostream &out) const;
public:
	// construction
	Vector4f() {}
	Vector4f(float x, float y, float z, float w=1.0f);
	Vector4f(const Vector4f &v);
	
	// access
	float *Ref(void) { return elts; }
	float &operator[](int i)       { return elts[i]; }
	const float operator[](int i) const { return elts[i]; }

	// assignment
	Vector4f& operator=(const Vector4f &rhs);
	const Vector4f& operator+=(const Vector4f &rhs);
	const Vector4f& operator-=(const Vector4f &rhs);

	// arithmetic operations
	const bool operator==(const Vector4f &rhs);

	// output
	friend ostream& operator <<(ostream &out, const Vector4f &v);
};

//typedef __declspec(align(16)) Vector4f Vector4f;

#endif