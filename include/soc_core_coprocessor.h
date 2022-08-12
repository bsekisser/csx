typedef struct soc_coprocessor_t** soc_coprocessor_h;
typedef struct soc_coprocessor_t* soc_coprocessor_p;
typedef struct soc_coprocessor_t* soc_coprocessor_p;

void soc_coprocessor_read(csx_p core, soc_coprocessor_p acp);
void soc_coprocessor_write(csx_p core, soc_coprocessor_p acp);
int soc_coprocessor_init(csx_p core);
