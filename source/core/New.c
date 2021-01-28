enum {
	INSTR_SET_A64,
	INSTR_SET_A32,
	INSTR_SET_T32,
}intstr_set_t;

void alu_write_pc(arm_p arm, uint32_t address)
{
	if(current_instr_set(arm) == _instr_set_a32)
		bx_write_pc(arm, address, _branch_type_indir);
	else
		branch_write_pc(arm, address, _branch_type_indir);
}

void branch_to(arm_p arm, uint32_t target)
{
	arm->reg[rPC] = target;
}

void branch_write_pc(arm_p arm, uint32_t address, branch_type_t branch_type)
{
	int thumb = !(current_instr_set(arm) == _instr_set_a32);
	
	address &= (~3 >> thumb);
	
	branch_to(arm, address, branch_type);
}

void bx_write_pc(arm_p arm, uint32_t address, branch_type_t branch_type)
{
	int thumb = BEXT(address, 0);
	
	uint32_t instr_set = thumb ? _instr_set_t32 : _instr_set_a32;
	
	select_instr_set(arm, instr_set);
	
	address &= ((~3) >> thumb);

	branch_to(arm, address, branch_type);
}

instr_set_t current_instr_set(arm_p arm)
{
	return(BEXT(PSTATE, PSTATE_BIT_T) ? INSTR_SET_T32 : ISNTR_SET_A32);
}

void alu_exception_return(arm_p arm, uint32_t address)
{
	if(!arm->spsr)
		return;

	exception_return(arm, address, *arm->spsr);
}

void exception_return(arm_p arm, uint32_t address, uint32_t spsr)
{
	set_state_from_psr(spsr);
	
	if(!spsr & PSR_I)
		new_pc &= ~3 >> pstate & PSR_T;

	branch_to(arm, new_pc, _branch_type_eret);
}

uint32_t this_instr_addr(arm_p arm)
{
	return(arm->ipc);
}
