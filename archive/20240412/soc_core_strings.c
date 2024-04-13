const char* arm_dpi_op_string[16] = {
	"and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc",
	"tst", "teq", "cmp", "cmn", "orr", "mov", "bic", "mvn",
};

const char* condition_code_string[2][16] = {
	{ "EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC",
	"HI", "LS", "GE", "LT", "GT", "LE", "", "" },
	{ "EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC",
	"HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV" },
};

const char* creg_name[16] = {
	"c0",	"c1",	"c2",	"c3",	"c4",	"c5",	"c6",	"c7",
	"c8",	"c9",	"c10",	"c11",	"c12",	"c13",	"c14",	"c15",
};


const char* reg_name[2][16] = {
	{ "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "rSP", "rLR", "rPC", },
	{ " r0", " r1", " r2", " r3", " r4", " r5", " r6", " r7", " r8", " r9", "r10", "r11", "r12", "rSP", "rLR", "rPC", },
};

const char* shift_op_string[2][6] = {
	{ "lsl", "lsr", "asr", "ror", },
	{ "LSL", "LSR", "ASR", "ROR", },
};
