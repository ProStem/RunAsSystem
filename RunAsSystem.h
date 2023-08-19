
// RunAsSystem - main.h - by Michael Badichi

#pragma once
#include <Windows.h>

void RunAsSystem( const WCHAR * cmd, DWORD * procDoneRetCode_ = NULL );
