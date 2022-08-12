static const char* _arm_creg_name(soc_core_reg_t r)
{
	const char* creg_names[16] = {
		"c0",	"c1",	"c2",	"c3",	"c4",	"c5",	"c6",	"c7",
		"c8",	"c9",	"c10",	"c11",	"c12",	"c13",	"c14",	"c15",
	};
	
	return(creg_names[r]);
}

static const char* _arm_reg_name(soc_core_reg_t r)
{
	const char* reg_names[16] = {
		"r0",	"r1",	"r2",	"r3",	"r4",	"r5",	"r6",	"r7",
		"r8",	"r9",	"r10",	"r11",	"r12",	"rSP",	"rLR",	"rPC",
	};
	
	return(reg_names[r]);
}
