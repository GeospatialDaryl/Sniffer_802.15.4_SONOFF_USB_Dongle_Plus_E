#ifndef MINITEST_H
#define MINITEST_H
#include <stdio.h>
#include <string.h>
/* printf.h (pulled in via console.h) remaps printf to the firmware printf; use fprintf */
static int mt_fail = 0, mt_run = 0;
#define CHECK(c) do { mt_run++; if(!(c)){ mt_fail++; fprintf(stdout, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);} } while(0)
#define CHECK_EQ(a,b) do { long long _a=(a), _b=(b); mt_run++; if(_a!=_b){ mt_fail++; fprintf(stdout, "  FAIL %s:%d: %s == %s (%lld vs %lld)\n", __FILE__, __LINE__, #a, #b, _a, _b);} } while(0)
#define CHECK_STR(a,b) do { mt_run++; if(strcmp((a),(b))){ mt_fail++; fprintf(stdout, "  FAIL %s:%d:\n    got:  %s\n    want: %s\n", __FILE__, __LINE__, (a), (b));} } while(0)
/* Documents a confirmed bug: reported as XFAIL while broken, FAILs once fixed (then convert to CHECK). */
static int mt_xfail = 0;
#define XFAIL(c, why) do { mt_run++; if(!(c)){ mt_xfail++; fprintf(stdout, "  XFAIL %s:%d: %s  [%s]\n", __FILE__, __LINE__, #c, why);} else { mt_fail++; fprintf(stdout, "  XPASS %s:%d: bug appears fixed, make this a CHECK: %s\n", __FILE__, __LINE__, #c);} } while(0)
#define RUN(t) do { fprintf(stdout, "%s\n", #t); t(); } while(0)
#define MT_DONE() do { fprintf(stdout, "%d checks, %d failed, %d known-bug (xfail)\n", mt_run, mt_fail, mt_xfail); return mt_fail ? 1 : 0; } while(0)
#endif
