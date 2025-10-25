#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>



int main(int argc, char *argv[]) {
    int ret = 0;

    const int a = 5;
    // a = 10; // This line would cause a compilation error if uncommented


    int x = 20;
    const int *ptr = &x;
    // *ptr = 30; // This line would cause a compilation error if uncommented
    x = 30; // This is allowed

    int *const cptr = &x;
    *cptr = 40; // This is allowed
    // cptr = &a; // This line would cause a compilation error if uncommented

    const int *const ccptr = &x;
    // *ccptr = 50; // This line would cause a compilation error if uncommented
    // ccptr = &a; // This line would cause a compilation error if uncommented

    // 每次遇到 const，就看看它“最近”的对象是谁（int 或 *），那个对象就是不可变的。

    return 0;
}