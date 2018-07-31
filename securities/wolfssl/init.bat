
@echo off

rem refer to setEnv.cmd in %SDK%\bin

set SDK_HOME=C:\Program Files\Microsoft SDKs\Windows\v7.1

; set PATH=C:\Program Files\Microsoft Visual Studio 10.0\Common7\IDE;
; set PATH=C:\Program Files\Microsoft Visual Studio 10.0\Common7\Tools;%PATH%
; set PATH=C:\Program Files\Microsoft Visual Studio 10.0\VC\Bin;%PATH%
; set PATH=C:\Program Files\Microsoft Visual Studio 10.0\VC\Bin\VCPackages;%PATH%
; set PATH=C:\Program Files\Microsoft SDKs\Windows\v7.1\Bin\NETFX 4.0 Tools;%PATH%

set PATH=%SDK_HOME%\Bin;%PATH%
; set PATH=C:\Windows\Microsoft.NET\Framework\v4.0.30319;%PATH%

; set INCLUDE=C:\Program Files\Microsoft Visual Studio 10.0\VC\INCLUDE;
set INCLUDE=%SDK_HOME%\INCLUDE;%INCLUDE%;
set INCLUDE=%SDK_HOME%\INCLUDE\gl;%INCLUDE%;

; set LIB=C:\Program Files\Microsoft Visual Studio 10.0\VC\Lib;
set LIB=%SDK_HOME%\Lib;%LIB%
; set LIB=C:\Windows\Microsoft.NET\Framework\v4.0.30319;%LIB%
; set LIB=C:\Windows\Microsoft.NET\Framework\v3.5;;%LIB%

rem build for Windows 7
set APPVER=6.1
set TARGETLANG=LANG_CHINESE
