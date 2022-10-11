#include <stdlib.h>
#include <stdio.h>
int main()
{
    int seed = 1633771873;
    srand(seed);
    for (int i = 0; i <= 9; ++i)
    {
        int v6 = rand() % 6 + 1;
        printf("-------------Turn:%d-------------\n", (unsigned int)(i + 1));
        printf("Please input your guess number:");
        printf("%d\n", v6);
        puts("---------------------------------");

        puts("Success!");
    }
    return 0;
}
