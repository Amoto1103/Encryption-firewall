#include <stdio.h>
#include <string.h>

unsigned int RSHash(char* str1, unsigned int len){   
	unsigned int b    = 378551;   
	unsigned int a    = 63689;   
	unsigned int hash = 0;   
	unsigned int i    = 0;    
	for(i = 0; i < len; str1++, i++)   {     
		hash = hash * a + (*str1);      
		a    = a * b;   }    
	return hash;}

/* End Of RS Hash Function */

/*
int main()
{
	char msg[]="apple";
	int a=0;
	a=RSHash(msg,strlen(msg));
	printf("result:%d\n",a);
}

*/