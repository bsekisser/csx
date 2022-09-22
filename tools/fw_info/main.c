#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* **** */

#include "fwinfo.h"

/* **** */

#include "err_test.h"
#include "log.h"

/* **** */

int main(int argc, char **argv)
{
	for(int i = 0; i < argc; i++)
		printf("%s:%s: argv[%d] == %s\n", __FILE__, __FUNCTION__, i, argv[i]);
	
	char *name = basename(argv[0]);
	
	printf("%s:%s: name == %s\n", __FILE__, __FUNCTION__, name);

	int flag = 0;

	if(0) for(int i = 1; i < argc; i++) {
		if(0 == strcmp(argv[i], "-flag"))
			flag = 1;
	}
	
	/* **** */
	
	int fd;
	ERR(fd = open(argv[1], O_RDONLY));

	struct stat sb;

	ERR(fstat(fd, &sb));
	
	void *data;
	ERR_NULL(data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0));
	
	fw_info_t fwi;
	rgn_get_fwinfo(data, sb.st_size, &fwi);

	munmap(data, sb.st_size);
	close(fd);
}
