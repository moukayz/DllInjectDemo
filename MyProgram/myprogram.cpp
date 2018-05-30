#include <stdio.h>
#include <Windows.h>

int main()
{
	int count = 0;
	while (TRUE)
	{
		Sleep(1000);
		//MessageBox(NULL, "haha", NULL, 0x30);
		printf("Count %d\n", count++);
	}

	return 0;
}