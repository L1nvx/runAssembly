#pragma once
#include <windows.h>
#include <amsi.h>
#include <iostream>

#pragma comment(lib, "Amsi.lib")

extern PVOID gAmsiHandler;
extern BYTE gAmsiOriginalByte;
extern void* gAmsiTargetAddr;

extern PVOID gEtwHandler;
extern BYTE gEtwOriginalByte;
extern void* gEtwTargetAddr;

int PatchAmsi();
int RevertPatchAmsi();
bool IsAmsiPatched();

int PatchETW();
int RevertPatchETW();
bool IsETWPatched();

int PatchAll();
int RevertAll();
bool IsEverythingPatched();