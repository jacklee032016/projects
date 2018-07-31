#ifndef __HUGICODE_H__
#define __HUGICODE_H__

#include "Vector4f.h"
#include "Matrix4f.h"

Vector4f MatrixMultiply1(Matrix4f &m, Vector4f &vin);
void MatrixMultiply2(Matrix4f &m, Vector4f *vin, Vector4f *vout);
void MatrixMultiply3(Matrix4f &m, Vector4f *vin, Vector4f *vout);
void BatchMultiply1(Matrix4f &m, Vector4f *vin, Vector4f *vout, int len);
void BatchMultiply2(Matrix4f &m, Vector4f *vin, Vector4f *vout, int len);
void BatchMultiply3(Matrix4f &m, Vector4f *vin, Vector4f *vout, int len);
void BatchMultiply4(Matrix4f &m, Vector4f *vin, Vector4f *vout, int len);
void BatchMultiply5(Matrix4f &m, Vector4f *vin, Vector4f *vout, int len);
void BatchTransform1(Matrix4f &m, Vector4f *vin, Vector4f *vout, int len);


#endif