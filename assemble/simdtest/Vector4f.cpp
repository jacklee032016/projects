#include "Vector4f.h"
#include <iostream>
#include <string.h>

using namespace std;

// constructors & destructor
Vector4f::Vector4f(float x, float y, float z, float w)
{
	elts[0] = x; elts[1] = y; elts[2] = z; elts[3] = w;
}
Vector4f::Vector4f(const Vector4f &v)
{
	elts[0] = v.elts[0];
	elts[1] = v.elts[1];
	elts[2] = v.elts[2];
	elts[3] = v.elts[3];
}

///////////// assignment
Vector4f& Vector4f::operator=(const Vector4f &rhs)
{
	if (this != &rhs)
		memcpy((*this).elts, rhs.elts, 4*sizeof(float));
	return *this;
}
const Vector4f& Vector4f::operator+=(const Vector4f &rhs)
{
	(*this)[0] += rhs[0];
	(*this)[1] += rhs[1];
	(*this)[2] += rhs[2];
	(*this)[3] += rhs[3];
	return *this;
}
const Vector4f& Vector4f::operator-=(const Vector4f &rhs)
{
	(*this)[0] -= rhs[0];
	(*this)[1] -= rhs[1];
	(*this)[2] -= rhs[2];
	(*this)[3] -= rhs[3];
	return *this;
}

///////////// arithmetic
const bool Vector4f::operator==(const Vector4f &rhs)
{
	return (	elts[0] == rhs[0] &&
				elts[1] == rhs[1] &&
				elts[2] == rhs[2] &&
				elts[3] == rhs[3] );
}


///////////// output
void Vector4f::print(ostream &out) const
{
	out << "<" << elts[0] << ", " << elts[1] << ", "
		<< elts[2] << ", " << elts[3] << ">";
}
ostream& operator<<(ostream &out, const Vector4f &v)
{
	v.print(out);
	return out;
}