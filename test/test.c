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
	int i = 10;
	char* buf = "hdjdjf";
	if( i <= 10)
	write(1, buf, sizeof(buf));
	foo();
	bar();
        return 0;
}
