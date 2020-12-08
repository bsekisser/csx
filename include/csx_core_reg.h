uint32_t csx_reg_get(csx_p csx, csx_reg_t r)
{
	uint32_t res = csx->reg[r & 0x0f];

	if(rPC == r)
		res += 4;
	else if(INSN_PC == r)
		csx->pc = res;

	return(res);
}

void csx_reg_set(csx_p csx, csx_reg_t r, uint32_t v)
{
	if(INSN_PC == r)
		csx->pc = v;

	csx->reg[r & 0x0f] = v;
}
