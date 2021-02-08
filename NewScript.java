//TODO write a description for this script

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.OpBehavior;
import ghidra.pcode.opbehavior.UnaryOpBehavior;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;
import ghidra.util.Msg;

public class NewScript extends GhidraScript {	
	private static final HashSet<String> DIT_GP_MNEMONICS = new HashSet<>(); 
	static {
		DIT_GP_MNEMONICS.addAll(Arrays.asList("ADC", "ADCS", "ADD", "ADDS", "AND", "ANDS", "ASR", "ASRV", "BFC", "BFI", "BFM", "BFXIL", "BIC", "BICS", "CCMN", "CCMP", "CFINV", "CINC", "CINV", "CLS", "CLZ", "CMN", "CMP", "CNEG", "CSEL", "CSET", "CSETM", "CSINC", "CSINV", "CSNEG", "EON", "EOR", "EXTR", "LSL", "LSLV", "LSR", "LSRV", "MADD", "MNEG", "MOV", "MOVK", "MOVN", "MOVZ", "MSUB", "MUL", "MVN", "NEG", "NEGS", "NGC", "NGCS", "NOP", "ORN", "ORR", "RBIT", "RET", "REV", "REV16", "REV32", "REV64", "RMIF", "ROR", "RORV", "SBC", "SBCS", "SBFIZ", "SBFM", "SBFX", "SETF8", "SETF16", "SMADDL", "SMNEGL", "SMSUBL", "SMULH", "SMULL", "SUB", "SUBS", "SXTB", "SXTH", "SXTW", "TST", "UBFIZ", "UBFM", "UBFX", "UMADDL", "UMNEGL", "UMSUBL", "UMULH", "UMULL", "UXTB", "UXTH"));
	}
	private static final HashSet<String> LDST_MNEMONICS = new HashSet<>();
	static {
		LDST_MNEMONICS.addAll(Arrays.asList("LD64B", "LDADD", "LDADDA", "LDADDAL", "LDADDL", "LDADDB", "LDADDAB", "LDADDALB", "LDADDLB", "LDADDH", "LDADDAH", "LDADDALH", "LDADDLH", "LDAPR", "LDAPRB", "LDAPRH", "LDAPUR", "LDAPURB", "LDAPURH", "LDAPURSB", "LDAPURSH", "LDAPURSW", "LDAR", "LDARB", "LDARH", "LDAXP", "LDAXR", "LDAXRB", "LDAXRH", "LDCLR", "LDCLRA", "LDCLRAL", "LDCLRL", "LDCLRB", "LDCLRAB", "LDCLRALB", "LDCLRLB", "LDCLRH", "LDCLRAH", "LDCLRALH", "LDCLRLH", "LDEOR", "LDEORA", "LDEORAL", "LDEORL", "LDEORB", "LDEORAB", "LDEORALB", "LDEORLB", "LDEORH", "LDEORAH", "LDEORALH", "LDEORLH", "LDLAR", "LDLARB", "LDLARH", "LDNP", "LDP", "LDPSW", "LDR", "LDRAA", "LDRAB", "LDRB", "LDRH", "LDRSB", "LDRSH", "LDRSW", "LDSET", "LDSETA", "LDSETAL", "LDSETL", "LDSETB", "LDSETAB", "LDSETALB", "LDSETLB", "LDSETH", "LDSETAH", "LDSETALH", "LDSETLH", "LDSMAX", "LDSMAXA", "LDSMAXAL", "LDSMAXL", "LDSMAXB", "LDSMAXAB", "LDSMAXALB", "LDSMAXLB", "LDSMAXH", "LDSMAXAH", "LDSMAXALH", "LDSMAXLH", "LDSMIN", "LDSMINA", "LDSMINAL", "LDSMINL", "LDSMINB", "LDSMINAB", "LDSMINALB", "LDSMINLB", "LDSMINH", "LDSMINAH", "LDSMINALH", "LDSMINLH", "LDTR", "LDTRB", "LDTRH", "LDTRSB", "LDTRSH", "LDTRSW", "LDUMAX", "LDUMAXA", "LDUMAXAL", "LDUMAXL", "LDUMAXB", "LDUMAXAB", "LDUMAXALB", "LDUMAXLB", "LDUMAXH", "LDUMAXAH", "LDUMAXALH", "LDUMAXLH", "LDUMIN", "LDUMINA", "LDUMINAL", "LDUMINL", "LDUMINB", "LDUMINAB", "LDUMINALB", "LDUMINLB", "LDUMINH", "LDUMINAH", "LDUMINALH", "LDUMINLH", "LDUR", "LDURB", "LDURH", "LDURSB", "LDURSH", "LDURSW", "LDXP", "LDXR", "LDXRB", "LDXRH", "ST64B", "ST64BV", "ST64BV0", "STADD", "STADDL", "STADDB", "STADDLB", "STADDH", "STADDLH", "STCLR", "STCLRL", "STCLRB", "STCLRLB", "STCLRH", "STCLRLH", "STEOR", "STEORL", "STEORB", "STEORLB", "STEORH", "STEORLH", "STLLR", "STLLRB", "STLLRH", "STLR", "STLRB", "STLRH", "STLUR", "STLURB", "STLURH", "STLXP", "STLXR", "STLXRB", "STLXRH", "STNP", "STP", "STR", "STRB", "STRH", "STSET", "STSETL", "STSETB", "STSETLB", "STSETH", "STSETLH", "STSMAX", "STSMAXL", "STSMAXB", "STSMAXLB", "STSMAXH", "STSMAXLH", "STSMIN", "STSMINL", "STSMINB", "STSMINLB", "STSMINH", "STSMINLH", "STTR", "STTRB", "STTRH", "STUMAX", "STUMAXL", "STUMAXB", "STUMAXLB", "STUMAXH", "STUMAXLH", "STUMIN", "STUMINL", "STUMINB", "STUMINLB", "STUMINH", "STUMINLH", "STUR", "STURB", "STURH", "STXP", "STXR", "STXRB", "STXRH"));
	}
	private enum InstrType {
		DIT, //this instruction is free to read any tainted value
		LDST, //this address of the destination cannot be a tainted value but the value being loaded/stored may be tainted
		NONDIT, //this instruction may not read any tainted value
	}
	
	HighFunction func;
	
	private void initAST() throws DecompileException {
		Function func = this.getFunctionContaining(this.currentAddress);
    	if(func == null) {
    		Msg.showWarn(this, 
				state.getTool().getToolFrame(), 
				"GraphAST Error", 
				"No Function at current location");
			return;
    	}
    	
    	DecompileOptions options = new DecompileOptions();
    	DecompInterface ifc = new DecompInterface();
    	ifc.setOptions(options);
    	
    	if (!ifc.openProgram(this.currentProgram)) {
			throw new DecompileException("Decompiler", "Unable to initialize: "+ifc.getLastMessage());
		}
    	
    	ifc.setSimplificationStyle("firstpass");
    	
    	DecompileResults res = ifc.decompileFunction(func, 30, null);
        this.func = res.getHighFunction();
	}
	
	private InstrType getMnemonicType(String mnemonic) {
		if(DIT_GP_MNEMONICS.contains(mnemonic.toUpperCase())) {
			return InstrType.DIT;
		}else if(LDST_MNEMONICS.contains(mnemonic.toUpperCase())) {
			return InstrType.LDST;
		}
		return InstrType.NONDIT;
	}
	
	private List<Instruction> findNonDitInstrs(Iterator<AddressRange> addrRanges) 
			throws MemoryAccessException, InsufficientBytesException, UnknownInstructionException, UnknownContextException {
		ArrayList<Instruction> res = new ArrayList<>();
		while(addrRanges.hasNext()) {
			AddressRange range = addrRanges.next();
			PseudoDisassembler disassembler = new PseudoDisassembler(currentProgram);

			Address curr = range.getMinAddress();
			while(curr.compareTo(range.getMaxAddress()) < 0) {
				Instruction instr = disassembler.disassemble(curr);
				
				if(getMnemonicType(instr.getMnemonicString()) == InstrType.NONDIT) {
					res.add(instr);
				}
				
				curr = curr.add(instr.getLength());
			}
		}
		
		return res;
	}
	
	private void assertTrue(boolean test, int idx) throws Exception{
		if(!test) {
			throw new Exception("failed assertion " + idx);
		}
	}
	
	//get the pcode op's that may have come before this one
	private List<PcodeOp> getPredecessors(PcodeOp op) throws Exception{
		ArrayList<PcodeOp> res = new ArrayList<>();
		
		PcodeBlockBasic block = op.getParent();
		SequenceNumber seqnum = op.getSeqnum();
		if(seqnum.getOrder() != 0) { 
			println("order " + seqnum.getOrder());
			//since this is a basic block, the only possible predecessor is the one preceeding this one in the block
			Iterator<PcodeOp> ops = block.getIterator();
			PcodeOp prev = null, next = null;
			for(int i = 0; i <= seqnum.getOrder(); i++) {
				prev = next;
				next = ops.next();
			}
			
			assertTrue(next.equals(op), 0);
			assertTrue(prev != null, 1);

			res.add(prev);
		}else {
			int insize = block.getInSize();
			for(int i = 0; i < insize; i++) {
				PcodeBlockBasic prevBlock = (PcodeBlockBasic)block.getIn(i);
				Iterator<PcodeOp> ops = prevBlock.getIterator();
				PcodeOp last = null;
				while(ops.hasNext()) {
					last = ops.next();
				}
				
				res.add(last);
			}
		}
		
		return res;
	}
	
	//returns a set of objects that could have influenced the value at the start of the current op's execution
	private Set<Object> getTaintSources(Varnode vn, HashSet<Varnode> visited) throws Exception {
		println("Checking taint source of " + vn.toString());
		HashSet<Object> res = new HashSet<>();
		
		if(visited.contains(vn)) {
			return res;
		}
		visited.add(vn);
		
		if(vn.isConstant()) { //constant varnode has no taint source
			return res;
		}else if(vn.isRegister() || vn.isUnique()) {
			PcodeOp op = vn.getDef();
			
			if(op == null) {
				println("reached end");
				return res;
			}
			
			PcodeOpRaw raw = new PcodeOpRaw(op);
			OpBehavior behave = raw.getBehavior();
			
			if(behave instanceof UnaryOpBehavior 
					|| behave instanceof BinaryOpBehavior) {
				for(Varnode input : op.getInputs()) {
					res.addAll(getTaintSources(input, visited));
				}
			}else if(behave.getOpCode() == PcodeOp.MULTIEQUAL) {
				for(Varnode input : op.getInputs()) {
					res.addAll(getTaintSources(input, visited));
				}
			}else {
				println("Unhandled pcode op: " + op.toString());
			}
			
		}else if(vn.isAddress()) {
			throw new Exception("Unhandled varnode address");
		}
		
		return res;
	}
	
	int nextIdx = 0;
	
	private void traceAddress(Varnode vn, HashMap<Varnode, Integer> visited) throws Exception {
		if(visited.containsKey(vn)) {
			printf("(%d)", visited.get(vn));
			return;
		}
		
		visited.put(vn, nextIdx++);
		printf("%d: ", visited.get(vn));
		
		if(vn.isRegister() || vn.isUnique()) {
			PcodeOp op = vn.getDef();
			
			if(op == null) {
				print(vn.toString());
				return;
			}
			
			PcodeOpRaw raw = new PcodeOpRaw(op);
			OpBehavior behave = raw.getBehavior();
			
			if(op.getOpcode() == PcodeOp.COPY) {
				traceAddress(op.getInput(0), visited);
				return;
			}
			
			print(op.getMnemonic());

			print(" ( ");
			
			for(int i = 0; i < op.getNumInputs(); i++) {
				traceAddress(op.getInput(i), visited);
				print(", ");
			}
			
			print(" ) ");
		}else {
			print(vn.toString());
		}
	}

    public void run() throws Exception {
    	this.initAST();
    	
    	Function f = func.getFunction();
    	Iterator<AddressRange> fiter = f.getBody().iterator();

    	List<Instruction> nonDitInstrs = findNonDitInstrs(fiter);
    	
    	println(currentAddress.toString());
    	
    	Iterator<PcodeOpAST> ops = func.getPcodeOps(currentAddress);
    	
    	HashSet<Varnode> inputs = new HashSet<>();
    	while(ops.hasNext()) {
    		PcodeOp p = ops.next();
    		
    		println(p.toString());

    		inputs.addAll(Arrays.asList(p.getInputs()));
    	}
    	
    	println(inputs.toString());
    	
    	for(Varnode input : inputs) {
    		try {
	    		println(input.toString());
	    		println(getTaintSources(input, new HashSet<>()).toString());
    		}catch(Exception e) {
    			e.printStackTrace();
    		}
    	}
    	
    	fiter = f.getBody().iterator();
    	
		ArrayList<Instruction> res = new ArrayList<>();
		while(fiter.hasNext()) {
			AddressRange range = fiter.next();
			PseudoDisassembler disassembler = new PseudoDisassembler(currentProgram);

			Address curr = range.getMinAddress();
			while(curr.compareTo(range.getMaxAddress()) < 0) {
				Instruction instr = disassembler.disassemble(curr);

				//println(instr.toString());
				Iterator<PcodeOpAST> instrOps = func.getPcodeOps(curr);
				while(instrOps.hasNext()){
					//println("    " + instrOps.next().toString());
					PcodeOpAST op = instrOps.next();
					if(op.getOpcode() == PcodeOp.LOAD) {
						println(curr.toString());
						nextIdx = 0;
						traceAddress(op.getInput(1), new HashMap());
						print("\n");
					}
				}

				
				curr = curr.add(instr.getLength());
			}
		}
    	
    }

}
