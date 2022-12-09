#include <stdio.h>
#include <stdlib.h>

// Library where getch() is stored
 
void bar(){
	int *a;
	for(int i = 0; i < 5; i++){
		write(1, "hello", 5);
	}
}

void foo(){
	FILE *p = open("hello.c", "r+");
	bar();
	close(p);
}
int main()
{
	//for(int i = 0; i < 10; i++)
	char* buf = "hdjdjf";
	write(1, buf, sizeof(buf));
	bar();
	foo();
        return 0;
}
