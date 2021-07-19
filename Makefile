
GOOD_WAT=$(wildcard test/good/*.wat)
GOOD_OBJ=$(subst .wat,.o,$(GOOD_WAT))
GOOD_RESULT=$(subst .wat,.res,$(GOOD_WAT))

BAD_WAT=$(wildcard test/bad/*.wat)
BAD_OBJ=$(subst .wat,.o,$(BAD_WAT))
BAD_OBJS=$(subst .wat,.osub,$(BAD_WAT)) # the object file but with the substitution performed
BAD_RESULT=$(subst .wat,.res,$(BAD_WAT))

GOOD_WASM=$(subst .wat,.wasm,$(GOOD_WAT))
BAD_WASM=$(subst .wat,.wasm,$(BAD_WAT))

nth_line = sed -n "$(2)p" < $(1) | tr -d '\n'

$(GOOD_OBJ) $(BAD_OBJ) : %.o : %.wasm Makefile
	./wasmtime.sh wasm2obj $*.wasm $*.o

$(GOOD_WASM) $(BAD_WASM) : %.wasm : %.wat Makefile
	./wat2wasm-strip.sh $*.wat -o $*.wasm

$(BAD_OBJS) : %.osub : %.subst %.o Makefile
	./do_substitution.sh $*

$(GOOD_RESULT) : %.res : %.o Makefile
	((./run_check.sh $*.o 2>&1 | tee $*.res | grep "VERDICT: Program admitted" > /dev/null) && echo "$* -- PASS") || echo "$* -- FAIL"

$(BAD_RESULT) : %.res : %.osub Makefile
	((./run_check.sh $*.osub 2>&1 | tee $*.res | grep "VERDICT: Program rejected" > /dev/null) && echo "$* -- PASS") || echo "$* -- FAIL"

bad_test: $(BAD_RESULT)

good_test: $(GOOD_RESULT)

test: $(BAD_RESULT) $(GOOD_RESULT);

clean:
	rm -f $(GOOD_OBJ) $(BAD_OBJ) $(BAD_OBJS) $(GOOD_RESULT) $(BAD_RESULT) $(GOOD_WASM) $(BAD_WASM)
