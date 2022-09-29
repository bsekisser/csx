const char* _condition_code_string[2][16] = {
	{ "EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC",
	"HI", "LS", "GE", "LT", "GT", "LE", "", "" },
	{ "EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC",
	"HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV" },
};

const char* dpi_op_string[16] = {
	"AND", "EOR", "SUB", "RSB", "ADD", "ADC", "SBC", "RSC",
	"TST", "TEQ", "CMP", "CMN", "ORR", "MOV", "BIC", "MVN",
};

const char* reg_name[16] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
	"r8", "r9", "r10", "r11", "r12", "SP", "LR", "PC",
};

const char* shift_op_string[6] = {
	"LSL", "LSR", "ASR", "ROR"
};
