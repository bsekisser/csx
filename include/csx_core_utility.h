static inline uint32_t _ror(uint32_t data, uint8_t shift)
{
	uint32_t l = data >> shift;
	uint32_t r = data << (32 - shift);
	
	return(l | r);
}
