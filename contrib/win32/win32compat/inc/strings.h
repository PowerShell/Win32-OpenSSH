#pragma once

#define bzero(p,l) memset((void *)(p),0,(size_t)(l))

void
explicit_bzero(void *b, size_t len);