extern char _heap_start;

extern
void* _sbrk(int bytes)
{
	static void* heap = 0;
	
	if(!heap)
		heap = &_heap_start;
	
	void *const prev_heap = heap;
	heap += bytes;
	
	return(prev_heap);
}
