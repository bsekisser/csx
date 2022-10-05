#define kRGN_MAGIC 0x7247704BUL
#define kRGN_VERSION 0x0064

enum {
	RGN_TYPE_LOADER = 0x0c,
	RGN_TYPE_FW_ALL = 0x0e,
};

typedef struct rgn_record_app_t* rgn_record_app_p;
typedef struct rgn_record_app_t {
	uint16_t version;
	uint8_t data[0];
	/* string: builder
	 * string: build date
	 * string: build time
	 */
}__attribute__((packed)) rgn_record_app_t;

typedef struct rgn_record_data_t* rgn_record_data_p;
typedef struct rgn_record_data_t {
	uint16_t version;
}__attribute__((packed)) rgn_record_data_t;

typedef struct rgn_record_region_t* rgn_record_region_p;
typedef struct rgn_record_region_t {
	uint16_t version;
	uint32_t delay;
	uint32_t size;
	uint8_t data[0];
}__attribute__((packed)) rgn_record_region_t;

typedef struct rgn_general_record_t* rgn_general_record_p;
typedef struct rgn_general_record_t {
	uint32_t length;
	uint8_t id;
/*	union {
		rgn_record_app_t app;
		rgn_record_data_t data;
		rgn_record_region_t region;
	};*/
}__attribute__((packed)) rgn_general_record_t;

typedef struct rgn_version_id_t* rgn_version_id_p;
typedef struct rgn_version_id_t {
	uint32_t signature;
	uint16_t version;
}__attribute__((packed)) rgn_version_id_t;

typedef struct rgn_file_header_t* rgn_file_header_p;
typedef struct rgn_file_header_t {
	rgn_version_id_t rgn_version_id;
	rgn_general_record_t rgn_record;
}__attribute__((packed)) rgn_file_header_t;
