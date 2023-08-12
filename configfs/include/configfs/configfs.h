#ifndef CONFIGFS_HEADER
#define CONFIGFS_HEADER

#include <string>
#if HAVE_FUSE3
#include <fuse3/fuse.h>
#else
#include <fuse.h>
#endif

#ifdef HAVE_FUSE3
#define DIR_FILLER(F,B,N,S,O) F(B,N,S,O,FUSE_FILL_DIR_PLUS)
#else
#define DIR_FILLER(F,B,N,S,O) F(B,N,S,O)
#endif

int configfs_loop(char* argv[]);

#endif