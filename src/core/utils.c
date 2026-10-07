#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int FindSubstring(char *buffer, long buffer_size, char *substring)
{
	int i = 0;
	int j = 0;
	for (i = 0; i < buffer_size; i++) {
		if (buffer[i] == substring[j]) {
			j++;
			if (j == strlen(substring)) {
				return i - strlen(substring) + 1;
			}
		} else {
			j = 0;
		}
	}
	return -1;
}
