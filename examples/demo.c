/* demo 目标：一个最小菜单程序，用来试 recorder。
 *   gcc -O0 -o demo demo.c
 */
#include <stdio.h>
#include <string.h>

int main(void) {
    char buf[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("DEMO-SVC v1");
    for (;;) {
        printf("Choice: ");
        if (!fgets(buf, sizeof buf, stdin)) break;
        if (buf[0] == '1') {
            printf("say something: ");
            if (!fgets(buf, sizeof buf, stdin)) break;
            printf("echo: %s", buf);
        } else if (buf[0] == '2') {
            printf("counter: %d\n", 42);
        } else if (buf[0] == '3') {
            puts("bye");
            break;
        } else {
            puts("?");
        }
    }
    return 0;
}
