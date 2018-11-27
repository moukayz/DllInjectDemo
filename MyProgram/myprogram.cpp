#include <stdio.h>
#include <Windows.h>

int main()
{
	int count = 0;
	while (TRUE)
	{
		//SleepEx(1000, TRUE);
		Sleep(1000);
		LoadLibraryA("KERNEL32.DLL");
		//MessageBox(NULL, "haha", NULL, 0x30);
		//printf("Count %d\n", count++);
	}

	return 0;
}