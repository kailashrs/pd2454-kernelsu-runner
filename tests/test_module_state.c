#include "kernel_module_state.h"
#include <assert.h>
static int test(const char *s){char b[512];strcpy(b,s);return ksu_module_buffer_live(b);}
int main(void){
 assert(test("kernelsu 180224 1 - Live 0x0 (O)\nother 1 0 - Live 0x0\n"));
 assert(test("other 1 0 - Live 0x0\nkernelsu 180224 1 - Live 0x0 (O)\n"));
 assert(!test("kernelsu 180224 1 - Loading 0x0 (O)\n"));
 assert(!test("kernelsu 180224 1 Live Loading 0x0\n"));
 assert(!test("kernelsu_extra 180224 1 - Live 0x0\n"));
 assert(!test("other 1 0 kernelsu, Live 0x0\n"));
 assert(!test("kernelsu 1\nother 1 0 - Live 0x0\n"));
 assert(!test(""));puts("PASS: readiness requires exact module name and Live state; Loading, dependency-name and truncated-line false positives rejected");
}
