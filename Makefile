
GOOD_WAT=$(wildcard test/good/*.wat)
GOOD_OBJ=$(subst .wat,.o,$(GOOD_WAT))
GOOD_RESULT=$(subst .wat,.res,$(GOOD_WAT))

BAD_WAT=$(wildcard test/bad/*.wat)
BAD_OBJ=$(subst .wat,.o,$(BAD_WAT))
BAD_OUT=$(subst .wat,.out,$(BAD_WAT))
BAD_RESULT=$(subst .wat,.res,$(BAD_WAT))

nth_line = sed -n "$(2)p" < $(1) | tr -d '\n'

$(GOOD_OBJ) $(BAD_OBJ) : %.o : %.wat Makefile
	./wasmtime.sh wasm2obj $*.wat $*.o

$(BAD_OUT) : %.out : %.subst %.o Makefile
	./do_substitution.sh $*

$(GOOD_RESULT) : %.res : %.o Makefile
	((./run_check.sh $*.o 2>/dev/null | grep "VERDICT: Program admitted" > /dev/null) && echo "$* -- PASS") || echo "$* -- FAIL"

$(BAD_RESULT) : %.res : %.out Makefile
	((./run_check.sh $*.out 2>/dev/null | grep "VERDICT: Program rejected" > /dev/null) && echo "$* -- PASS") || echo "$* -- FAIL"

test: $(BAD_RESULT) $(GOOD_RESULT);

clean:
	rm $(GOOD_OBJ) $(BAD_OBJ) $(BAD_OUT)