typedef struct csx_coprocessor_t** csx_coprocessor_h;
typedef struct csx_coprocessor_t* csx_coprocessor_p;
typedef struct csx_coproc_data_t* csx_coproc_data_p;

void csx_coprocessor_read(csx_p core, csx_coproc_data_p acp);
void csx_coprocessor_write(csx_p core, csx_coproc_data_p acp);
int csx_coprocessor_init(csx_p core);
