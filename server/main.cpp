#include <stdio.h>

int main(void) {
#ifdef LITTLE_ENDIAN
    printf("HEllo World!\n");
#else
    printf("HEllo World!2\n");
#endif
}