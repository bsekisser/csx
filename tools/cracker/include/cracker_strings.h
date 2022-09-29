extern const char* _condition_code_string[2][16];
extern const char* dpi_op_string[16];
extern const char* reg_name[16];
extern const char* shift_op_string[6];

#define CCs(_x) _condition_code_string[_x][CCx]
