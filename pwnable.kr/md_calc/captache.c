#include <stdlib.h>
#include <stdio.h>

int get_canary(int seed, int captcha)
{
	int random_number[8] = {0};
	srand(seed);

	int i;
	for(i = 0; i < 8; i++)
	{
		random_number[i] = rand();
	}

	return captcha - (random_number[1] + random_number[5] + 
						random_number[2] - random_number[3] + 
						random_number[7] + random_number[4] - random_number[6]);
}
