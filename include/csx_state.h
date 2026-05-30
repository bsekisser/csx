#pragma once

typedef union csx_state_tag {
	unsigned raw_flags;
	struct {
		char halt:1;
		char run:1;
		struct {
			char read:1;
			char write:1;
		}invalid;
	};
}csx_state_t;
