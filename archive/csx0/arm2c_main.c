
ac_t {
	void *btrace_list;
}ac_t;

void add_btrace(ac_p ac, uint32_t address)
{
	
}

void btrace(ac_p ac);
{
	uint32_t ip = ac->ip;
	uint32_t *code = &ac->data[ip++];
	
	uint32_t opcode = *code;
	
}

void main(void)
{
	int fd;

	LOG("opening " LOCAL_RGNDIR RGNFileName "_loader.bin...");

	ERR(fd = open(LOCAL_RGNDIR RGNFileName "_loader.bin", O_RDONLY));

	struct stat sb;
	ERR(fstat(fd, &sb));
	
	void *data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	ERR_NULL(data);
	
	uint32_t data_size = sb.st_size;
	
	close(fd);
	
	ac->data = data;
	ac->ip = 0;
	
	btrace(ac);
}
