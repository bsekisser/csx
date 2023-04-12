static int _soc_core_test_trace(soc_core_p core, int trace, int* restore)
{
	int savedTrace = core->trace;

	if(restore) {
		core->trace = !!(*restore);
	} else if(trace) {
		core->trace = 1;
	}
	
	return(savedTrace);
}
