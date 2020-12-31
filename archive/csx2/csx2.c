#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

#include "../../include/err_test.h"

#define LOCAL_RGNDIR "../garmin/rgn_files/"
#include "../../garmin/rgn_files/038201000610.h"

void csx2(void *data);

int main(void)
{
	int fd;

	printf("\n\n\t/*\n\t *\n");
	printf("\t * opening " LOCAL_RGNDIR RGNFileName "_loader.bin...\n");
	printf("\t *\n\t */\n\n\n");

	ERR(fd = open(LOCAL_RGNDIR RGNFileName "_loader.bin", O_RDONLY));

	struct stat sb;
	ERR(fstat(fd, &sb));
	
	void *data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	ERR_NULL(data);

	csx2(data);
	
	return(0);
}
