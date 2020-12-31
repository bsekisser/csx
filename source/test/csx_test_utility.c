void _cxx(csx_test_p t, uint32_t value, uint8_t size)
{
	for(int i = 0; i < size; i++)
		t->code[t->pc++] = (value >> ((i) << 3)) & 0xff;
}
