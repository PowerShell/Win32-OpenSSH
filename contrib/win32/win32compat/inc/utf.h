/*
* Author: Manoj Ampalam <manoj.ampalam@microsoft.com>
*
* UTF-16 <--> UTF-8 definitions
*/
#pragma once
#ifndef UTF_H
#define UTF_H 1

wchar_t* utf8_to_utf16(const char *);
char* utf16_to_utf8(const wchar_t*);

#endif