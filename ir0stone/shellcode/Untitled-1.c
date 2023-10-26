#include <stdio.h>
#include <string.h>

int main()
{
    int n;
    scanf("%d", &n);

    int h[n];
    for (int i = 0; i < n; i++)
        scanf("%d", &h[i]);

    int kpk = h[0];
    for (int i = 1; i < n; i++)
    {
        int temp = 0;
        int x = kpk;
        int y = h[i];
        while (y != 0)
        {
            temp = y;
            y = x % y;
            x = temp;
        }
        kpk *= (h[i] / x);
    }
    char hari[7][7] = {"Minggu", "Senin", "Selasa", "Rabu", "Kamis", "Jumat", "Sabtu"};
    char hari_pertama[7];
    printf("%d\n", kpk);
    scanf("%s", hari_pertama);
    for (int i = 0; i < 7; i++)
    {
        if (strcmp(hari_pertama, hari[i]) == 0)
        {
            printf("%s\n", hari[(i + kpk) % 7]);
            break;
        }
    }
    return 0;
}