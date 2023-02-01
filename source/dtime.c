#define __GNU_SOURCE

#include <inttypes.h>
#include <time.h> // clock_gettime
#include <unistd.h> // sleep
#include <stdio.h> // printf
#include <stdint.h>

#include "dtime.h"

static uint64_t calibrate_get_dtime_loop(void)
{
   	uint64_t start = get_dtime();
   	uint64_t elapsedTime = _get_dtime_elapsed(start);

	int i;
	for(i=1; i<=1024; i++) {
		start = get_dtime();
		elapsedTime += _get_dtime_elapsed(start);
	}
		
	return(elapsedTime / i);
	
}

static uint64_t calibrate_get_dtime_sleep(void)
{
   	uint64_t start = get_dtime();
	
	sleep(1);
		
	return(_get_dtime_elapsed(start));
}

uint64_t dtime_calibrate(void)
{
	uint64_t cycleTime = calibrate_get_dtime_loop();
	uint64_t elapsedTime, ecdt;
	double emhz;

	printf("%s: calibrate_get_dtime_cycles(%016" PRIu64 ")\n", __FUNCTION__, cycleTime);

	elapsedTime = 0;

	for(int i = 1; i <= 3; i++) {
		elapsedTime += (calibrate_get_dtime_sleep() - cycleTime);

		ecdt = elapsedTime / i;
		emhz = (double)ecdt / MHz(1.0);
		printf("%s: elapsed time: %016" PRIu64 ", ecdt: %016" PRIu64 ", estMHz: %010.4f\n", __FUNCTION__, elapsedTime, ecdt, emhz);
	}
	return(ecdt);
}
