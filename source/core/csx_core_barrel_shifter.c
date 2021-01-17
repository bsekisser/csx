static uint32_t _csx_core_arm_shifter_operation_asr(csx_core_p core, uint32_t vin, uint8_t shift, uint8_t* cout)
{
	uint8_t asr_shift = shift & _BM(6);

	if(!asr_shift && BTST(shift, 7))
		asr_shift = 32;

	if(asr_v)
		*cout = BEXT(vin, asr_shift - 1);
	else
		*cout = BEXT(CPSR, CSX_PSR_BIT_C);

	return((signed)vin >> asr_shift);
}

static uint32_t _csx_core_arm_shifter_operation_lsl(csx_core_p core, uint32_t vin, uint8_t shift, uint8_t* cout)
{
	if(shift)
		*cout = BEXT(vin, 32 - shift);
	else
		*cout = BEXT(CPSR, CSX_PSR_BIT_C);

	return(vin << shift);
}

static uint32_t _csx_core_arm_shifter_operation_lsr(csx_core_p core, uint32_t vin, uint8_t shift, uint8_t* cout)
{
	uint8_t lsr_shift = shift & _BM(6);

	if(!lsr_shift && BTST(shift, 7))
		lsr_shift = 32;

	if(lsr_shift)
		*cout = BEXT(vin, lsr_shift - 1);
	else
		*cout = BEXT(CPSR, CSX_PSR_BIT_C);

	return(vin >> lsr_shift);
}


uint32_t csx_core_barrel_shifter(csx_core_p core, uint32_t vin, uint32_t shift, uint8_t*cout, uint8_t shopt)
{
	switch(shopt)
	{
		case CSX_SHIFTER_OP_ASR:
			return(_csx_core_arm_shifter_operation_asr(core, vin, shift, cout));
			break;
		case CSX_SHIFTER_OP_LSL:
			return(_csx_core_arm_shifter_operation_lsl(core, vin, shift, cout));
			break;
		case CSX_SHIFTER_OP_LSR:
			return(_csx_core_arm_shifter_operation_lsr(core, vin, shift, cout));
			break;
}
