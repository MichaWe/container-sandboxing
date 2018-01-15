#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
	FILE *s = fopen("/etc/shadow", "r");
	char buffer[2048];
	if (!s) {
		printf("File open failed!\n");
		return 1;
	}
	while (!feof(s)) {
		memset(buffer, 0, 2048);
		fread(buffer, 2048, 1, s);
		printf("%s", buffer);
	}
	return 0;
}
