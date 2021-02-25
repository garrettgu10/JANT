//TODO write a description for this script

import java.util.ArrayList;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.OpBehavior;
import ghidra.pcode.opbehavior.UnaryOpBehavior;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.address.*;

import com.google.gson.*;

class MemoriesVmctxData {
	boolean imported;
	boolean secret;
}

class FunctionsVmctxData {
	boolean[] paramSecrecy;
	boolean[] returnSecrecy;
	boolean trusted;
}

class VmctxOffsetData {
	int globalsOffset;
	boolean[] globalsSecrecy;
	int memoriesOffset;
	MemoriesVmctxData[] memories;
	FunctionsVmctxData[] functions;
}

//lets you check if an arbitrary varnode contains a value that is possibly tainted
class TaintHelper {
	DITChecker main;
	VmctxOffsetData vmctx;
	
	public TaintHelper(DITChecker m, VmctxOffsetData vmctx) {
		this.main = m;
		this.vmctx = vmctx;
	}
	
	//checks if an initial Varnode (one with no source) is tainted
	private boolean checkInitialTaint(Varnode vn) {
		if(vn.getDef() != null) {
			throw new IllegalArgumentException("Varnode must be initial");
		}
		if(!vn.isRegister()) {
			throw new IllegalArgumentException("Varnode must be a register");
		}
		
		String description = main.getRegisterName(vn);
		
		if(description.equals("sp") || description.equals("x30")) {
			return false; //the stack pointer and return address are not considered secret when the function starts running
		}

		int funcIndex = main.currentFunctionIndex;
		boolean[] paramSecrecy = vmctx.functions[funcIndex].paramSecrecy;
		char regPrefix = description.charAt(0);
		
		if(regPrefix != 'w' && regPrefix != 'x') {
			throw new RuntimeException("Unhandled register prefix for register: " + description);
		}
		
		int regIndex = Integer.parseInt(description.substring(1));
		
		if(regIndex == 0) {
			return false; //the location of the vmctx is not tainted
		}
		
		if(regIndex > 6 || regIndex >= paramSecrecy.length + 2) {
			throw new RuntimeException("Unhandled register index for: " + description);
		}
		
		return paramSecrecy[regIndex - 2]; //the first 6 arguments are passed in through x2-x7
	}
	
	//returns false if we are sure the value is not tainted
	private boolean checkIsTainted(Varnode vn, HashSet<Varnode> visited) {
		boolean res = false;
		
		if(visited.contains(vn)) { // cycle detected, but we are able to determine the true taintedness from the other check
			return false;
		}
		visited.add(vn);
		
		if(vn.isRegister() && main.getRegisterName(vn).equals("x30")) {
			main.println(main.decomposeAddr(vn));
		}
		
		if(vn.isConstant() || vn.isAddress()) { 
			//constant varnode has no taint
			//likewise, a hardcoded address has no taint since the address is obtainable statically
			//we perform a separate check for loaded values
			return false;
		}else if(vn.isRegister() || vn.isUnique()) {
			PcodeOp op = vn.getDef();
			
			if(op == null) {
				return checkInitialTaint(vn);
			}
			
			PcodeOpRaw raw = new PcodeOpRaw(op);
			OpBehavior behave = raw.getBehavior();
			
			if(behave instanceof UnaryOpBehavior 
					|| behave instanceof BinaryOpBehavior) {
				for(Varnode input : op.getInputs()) {
					res |= checkIsTainted(input, visited);
				}
			}else if(behave.getOpCode() == PcodeOp.MULTIEQUAL) {
				for(Varnode input : op.getInputs()) {
					res |= checkIsTainted(input, visited);
				}
			}else if(behave.getOpCode() == PcodeOp.LOAD) {
				if(!main.isRAM(op.getInput(0))) {
					throw new RuntimeException("Unhandled load target: " + op.getInput(0).toString());
				}
				return main.checkAddressTainted(op.getInput(1));
			}else {
				throw new RuntimeException("Unhandled pcode op: " + op.toString());
			}
			
		}else{
			throw new RuntimeException("Unhandled varnode type: " + vn.toString());
		}
		
		return res;
	}
	
	public boolean isTainted(Varnode v) {
		return checkIsTainted(v, new HashSet<>());
	}
}

//lets you check if some arbitrary memory load is from a tainted source
class MemoryHelper {	
	DITChecker main;

	ArrayList<ASTNode> secretAddresses; 
	// a load from this address will yield a tainted value and a store may be tainted
	ArrayList<ASTNode> publicAddresses; 
	// a load from this address will yield an untainted value and a store must be untainted
	
	ASTNode stack = new AnyOffset(new RegisterNode("sp"));

	public MemoryHelper(DITChecker m, VmctxOffsetData vmctx) {
		this.main = m;
		secretAddresses = new ArrayList<>();
		publicAddresses = new ArrayList<>();
		
		//add the global stack bound
		publicAddresses.add(new RegisterNode("x0"));
		publicAddresses.add(new Load(new RegisterNode("x0")));
		
		//loading from any constant address is considered public
		//this also means we do not allow writing secret values to a constant address
		publicAddresses.add(new AnyConst());
		
		for(int i = 0; i < vmctx.globalsSecrecy.length; i++) {
			ASTNode toAdd = new SpecificOffset(new RegisterNode("x0"), vmctx.globalsOffset + 0x10 * i);
			if(vmctx.globalsSecrecy[i]) {
				secretAddresses.add(toAdd);
			}else {
				publicAddresses.add(toAdd);
			}
		}
		for(int i = 0; i < vmctx.memories.length; i++) {
			ASTNode firstPtr = new SpecificOffset(new RegisterNode("x0"), vmctx.memoriesOffset + 0x10 * i);
			publicAddresses.add(firstPtr);
			ASTNode secondPtr = new Load(firstPtr);
			publicAddresses.add(secondPtr);
			
	    	ASTNode finalLevel = new AnyOffset(new Load(secondPtr));
	    	if(vmctx.memories[i].secret) {
	    		secretAddresses.add(finalLevel);
	    	}else {
	    		publicAddresses.add(finalLevel);
	    	}
		}
	}
	
	interface ASTNode {
		boolean matches(Varnode v);
	}
	
	class ConcreteValue implements ASTNode {
		long value;
		public ConcreteValue(long v) {
			this.value = v;
		}
		
		@Override
		public String toString() {
			return "0x" + Long.toString(value, 16);
		}
		
		public boolean matches(Varnode v) {
			if(v.isConstant()) {
				return value == v.getOffset();
			}
			PcodeOp op = v.getDef();
			if(op == null) return false;
			if(op.getOpcode() == PcodeOp.COPY) {
				return matches(op.getInput(0));
			}
			return false;
		}
	}
	
	class AnyOffset implements ASTNode {
		ASTNode addr;
		
		public AnyOffset(ASTNode a) {
			this.addr = a;
		}
		
		@Override
		public String toString() {
			return "( " + addr + " + x )";
		}
		
		public boolean matches(Varnode v) {
			if(addr.matches(v)) {
				return true;
			}
			PcodeOp op = v.getDef();
			if(op == null) return false;
			if(op.getOpcode() == PcodeOp.COPY) {
				return matches(op.getInput(0));
			}else if(op.getOpcode() == PcodeOp.INT_ADD || op.getOpcode() == PcodeOp.INT_SUB) {
				return matches(op.getInput(0)) && !main.isTainted(op.getInput(1));
			}
			return false;
		}
	}
	
	class AnyConst implements ASTNode {
		public String toString() {
			return "c";
		}
		
		public boolean matches(Varnode v) {
			PcodeOp op = v.getDef();
			if(op == null) return v.isConstant();
			if(op.getOpcode() == PcodeOp.COPY) return matches(op.getInput(0));
			return false;
		}
	}
	
	class Load implements ASTNode {
		ASTNode addr;
		
		public Load(ASTNode a) {
			this.addr = a;
		}
		
		@Override
		public String toString() {
			return "*( " + addr + " )";
		}
		
		public boolean matches(Varnode v) {
			PcodeOp op = v.getDef();
			if(op == null) return false;
			if(op.getOpcode() == PcodeOp.COPY) {
				return matches(op.getInput(0));
			}else if(op.getOpcode() == PcodeOp.LOAD) {
				return main.isRAM(op.getInput(0)) && addr.matches(op.getInput(1));
			}
			return false;
		}
	}
	
	class SpecificOffset implements ASTNode {
		ASTNode base;
		long offset;
		
		public SpecificOffset(ASTNode base, long offset) {
			this.base = base;
			this.offset = offset;
		}
		
		@Override
		public String toString() {
			return "( " + base + " + " + offset + " )";
		}
		
		public boolean matches(Varnode v) {
			if(offset == 0) return base.matches(v);
			
			PcodeOp op = v.getDef();
			if(op == null) return false;
			if(op.getOpcode() == PcodeOp.COPY) {
				return matches(op.getInput(0));
			}else if(op.getOpcode() == PcodeOp.INT_ADD) {
				Varnode left = op.getInput(0);
				Varnode right = op.getInput(1);
				if(right.isConstant()) {
					return new SpecificOffset(base, offset - right.getOffset()).matches(left);
				}
			}
			return false;
		}
	}
	
	class RegisterNode implements ASTNode {
		String registerName;
		
		public RegisterNode(String name) {
			this.registerName = name;
		}
		
		@Override
		public String toString() {
			return registerName;
		}
		
		public boolean matches(Varnode v) {
			PcodeOp op = v.getDef();
			if(op == null) {
				if(v.isRegister()) {
					return registerName.equals(main.getRegisterName(v));
				}
				return false;
			}else if(op.getOpcode() == PcodeOp.COPY) {
				return matches(op.getInput(0));
			}
			
			return false;
		}
	}
	
	public SpecificOffset flattenStackAddr(Varnode v) {
		if(!stack.matches(v)) {
			throw new RuntimeException("Attempted to flatten non-stack address");
		}
		PcodeOp op = v.getDef();
		if(op == null) {
			if(!v.isRegister() || !main.getRegisterName(v).equals("sp")) {
				throw new RuntimeException("Failed to flatten stack pointer");
			}
			return new SpecificOffset(new RegisterNode("sp"), 0);
		}else if(op.getOpcode() == PcodeOp.COPY) {
			return flattenStackAddr(op.getInput(0));
		}else if(op.getOpcode() == PcodeOp.INT_ADD) {
			SpecificOffset lhs = flattenStackAddr(op.getInput(0));
			lhs.offset += main.resolveValue(op.getInput(1));
			return lhs;
		}else {
			throw new RuntimeException("Could not handle op " + op + " when attempting to flatten stack address");
		}
	}

	public boolean checkAddressTainted(Varnode vn) {
		for(ASTNode secretAddr : secretAddresses) {
			if(secretAddr.matches(vn)) {
				return true;
			}
		}
		for(ASTNode publicAddr : publicAddresses) {
			if(publicAddr.matches(vn)) {
				return false;
			}
		}
		
		if(stack.matches(vn)) {
			main.println("Found stack match");
			main.println(flattenStackAddr(vn).toString());
		}
		
		throw new RuntimeException("Cannot resolve address: " + decomposeAddr(vn, new HashMap<>()));
	}
	
	int nextIdxForDecomposition = 0;
	public String decomposeAddr(Varnode vn, HashMap<Varnode, Integer> visited) {
		if(visited.containsKey(vn)) {
			return String.format("(%d)", visited.get(vn));
		}
		
		StringBuilder res = new StringBuilder();
		
		visited.put(vn, nextIdxForDecomposition++);
		res.append(String.format("%d: ", visited.get(vn)));
		
		if(vn.isRegister() || vn.isUnique()) {
			PcodeOp op = vn.getDef();
			
			if(op == null) {
				res.append(vn.isRegister()? main.getRegisterName(vn) : vn.toString());
				return res.toString();
			}
			
			if(op.getOpcode() == PcodeOp.COPY) {
				res.append(decomposeAddr(op.getInput(0), visited));
				return res.toString();
			}
			
			res.append(op.getMnemonic());

			res.append(" ( ");
			
			for(int i = 0; i < op.getNumInputs(); i++) {
				res.append(decomposeAddr(op.getInput(i), visited));
				res.append(", ");
			}
			
			res.append(" ) ");
		}else {
			res.append(vn.toString());
		}
		
		return res.toString();
	}

}

//handles information pertaining to the ARM DIT specification
class DITHelper {	
	private static final HashSet<String> DIT_GP_MNEMONICS = new HashSet<>(); 
	static {
		DIT_GP_MNEMONICS.addAll(Arrays.asList("ADC", "ADCS", "ADD", "ADDS", "AND", "ANDS", "ASR", "ASRV", "BFC", "BFI", "BFM", "BFXIL", "BIC", "BICS", "CCMN", "CCMP", "CFINV", "CINC", "CINV", "CLS", "CLZ", "CMN", "CMP", "CNEG", "CSEL", "CSET", "CSETM", "CSINC", "CSINV", "CSNEG", "EON", "EOR", "EXTR", "LSL", "LSLV", "LSR", "LSRV", "MADD", "MNEG", "MOV", "MOVK", "MOVN", "MOVZ", "MSUB", "MUL", "MVN", "NEG", "NEGS", "NGC", "NGCS", "NOP", "ORN", "ORR", "RBIT", "REV", "REV16", "REV32", "REV64", "RMIF", "ROR", "RORV", "SBC", "SBCS", "SBFIZ", "SBFM", "SBFX", "SETF8", "SETF16", "SMADDL", "SMNEGL", "SMSUBL", "SMULH", "SMULL", "SUB", "SUBS", "SXTB", "SXTH", "SXTW", "TST", "UBFIZ", "UBFM", "UBFX", "UMADDL", "UMNEGL", "UMSUBL", "UMULH", "UMULL", "UXTB", "UXTH"));
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
	
	private static InstrType getMnemonicType(String mnemonic) {
		if(DIT_GP_MNEMONICS.contains(mnemonic.toUpperCase())) {
			return InstrType.DIT;
		}else if(LDST_MNEMONICS.contains(mnemonic.toUpperCase())) {
			return InstrType.LDST;
		}
		return InstrType.NONDIT;
	}
	
	//returns a list of instructions not covered by DIT
	public static List<Instruction> findNonDitInstrs(Program currentProgram, Iterator<AddressRange> addrRanges) {
		ArrayList<Instruction> res = new ArrayList<>();
		while(addrRanges.hasNext()) {
			AddressRange range = addrRanges.next();
			PseudoDisassembler disassembler = new PseudoDisassembler(currentProgram);

			Address curr = range.getMinAddress();
			while(curr.compareTo(range.getMaxAddress()) < 0) {
				Instruction instr;
				try {
					instr = disassembler.disassemble(curr);
				}catch(Exception e) {
					throw new RuntimeException("Failed to disassemble instruction at location " + curr);
				}
				
				if(getMnemonicType(instr.getMnemonicString()) == InstrType.NONDIT) {
					//In this case, it is acceptable to include LD/ST mnemonics, since these are checked separately
					res.add(instr);
				}
				
				curr = curr.add(instr.getLength());
			}
		}
		
		return res;
	}
}

//represents a single pass through the function to check for some property
interface DITCheckPass {
	boolean check(DITChecker main);
}

class NonDITInstrCheckPass implements DITCheckPass {
	public String toString() {
		return "Check that no inputs to a non-DIT instruction are secret-dependent";
	}

	@Override
	public boolean check(DITChecker main) {
		Program cp = main.currentProgram;
		HighFunction func = main.currentFunction;
		List<Instruction> nonDitInstrs = DITHelper.findNonDitInstrs(cp, func.getFunction().getBody().iterator());
		for(Instruction instr : nonDitInstrs) {
			Iterator<PcodeOpAST> ops = func.getPcodeOps(instr.getAddress());
			
			while(ops.hasNext()) {
				PcodeOpAST op = ops.next();
				
				if(op.getOpcode() == PcodeOp.INDIRECT
						&& op.getInput(0).toString().equals(op.getOutput().toString())) {
					//this is a false data dependency -- the indirect opcode only exists to warn that the varnode may be mutated
					//it is safe to ignore this pcode op
					continue;
				}
				
				for(Varnode input : op.getInputs()) {
					if(main.isTainted(input)) {
						main.println("Input " + main.getRegisterName(input) + " is tainted at " + instr.getAddress().toString());
						return false;
					}
				}
			}
		}
		
		return true;
	}
}

class SecretStoresCheckPass implements DITCheckPass {
	public String toString() {
		return "Check that a secret value is never written to a public location";
	}
	
	@Override
	public boolean check(DITChecker main) {
		HighFunction func = main.currentFunction;
		Iterator<PcodeOpAST> ops = func.getPcodeOps();
		
		while(ops.hasNext()) {
			PcodeOpAST op = ops.next();
			if(op.getOpcode() != PcodeOp.STORE) continue;
						
			Varnode addr = op.getInput(1);
			Varnode toStore = op.getInput(2);
			
			if(!main.checkAddressTainted(addr)) {
				// we are storing to a public location
				if(main.isTainted(toStore)) {
					return false;
				}
			}
		}
		
		return true;
	}
}

class TaintedAddrCheckPass implements DITCheckPass {
	public String toString() {
		return "Check that no target addresses of loads/stores are secret-dependent";
	}

	@Override
	public boolean check(DITChecker main) {
		HighFunction func = main.currentFunction;
		Iterator<PcodeOpAST> ops = func.getPcodeOps();
		
		while(ops.hasNext()) {
			PcodeOpAST op = ops.next();
			
			if(op.getOpcode() != PcodeOp.STORE && op.getOpcode() != PcodeOp.LOAD) continue;
			
			Varnode addr = op.getInput(1);
			
			if(main.isTainted(addr)) {
				//we use isTainted here instead of checkAddressTainted since we are interested in
				//whether the address's value itself is tainted, not whether the value that's supposed
				//to be at the address is tainted
				
				return false;
			}
		}
		
		return true;
	}
}

class TrustedFunctionCallPass implements DITCheckPass {
	public String toString() {
		return "Check that a trusted function is never called by an untrusted function";
	}

	@Override
	public boolean check(DITChecker main) {
		//since we are running checks, the current function must be untrusted
		//we need to ensure it never calls a trusted function
		HighFunction func = main.currentFunction;
		Iterator<PcodeOpAST> ops = func.getPcodeOps();
		
		while(ops.hasNext()) {
			PcodeOpAST op = ops.next();
			int opcode = op.getOpcode();
			if(opcode == PcodeOp.CALL
			   || opcode == PcodeOp.BRANCH
			   || opcode == PcodeOp.CBRANCH) {
				Varnode dest = op.getInput(0);
				
				if(dest.isConstant()) {
					//pcode-relative branching, this is a branch within the same instruction
					continue;
				}
				if(main.currentFunction.getFunction().getBody().contains(dest.getAddress())) {
					//this is a branch within the function, nothing to see here
					continue;
				}
				Function targetFunc = main.currentProgram.getFunctionManager().getFunctionAt(dest.getAddress());
				
				if(targetFunc == null) {
					throw new RuntimeException("Cannot find function starting at " + dest.getAddress());
				}
				
			}else if(opcode == PcodeOp.CALLIND || opcode == PcodeOp.BRANCHIND) {
				long destOff = main.resolveValue(op.getInput(0));
				AddressSpace currentAddressSpace = main.currentFunction.getFunction().getEntryPoint().getAddressSpace();
				Address targetAddr = currentAddressSpace.getAddress(destOff);
				
				if(main.funcIsTrusted(targetAddr)) {
					return false;
				}
			}
		}

		return true;
	}
}

class FunctionParameterPass implements DITCheckPass {
	public String toString() {
		return "Check that a tainted parameter is never passed to a function expecting a public value [TODO]";
	}

	@Override
	public boolean check(DITChecker main) {
		// TODO Auto-generated method stub
		return false;
	}
}

//encapsulates everything needed to verify a single function
class DITChecker {
	NewScript script;
	VmctxOffsetData vmctx;
	Program currentProgram;
	private TaintHelper tc;
	private MemoryHelper mc;
	HighFunction currentFunction;
	int currentFunctionIndex = -1;
	
	ArrayList<DITCheckPass> checks = new ArrayList<>();
	{
		checks.add(new NonDITInstrCheckPass());
		checks.add(new TaintedAddrCheckPass());
		checks.add(new SecretStoresCheckPass());
		checks.add(new TrustedFunctionCallPass());
		checks.add(new FunctionParameterPass());
		//TODO: add data dependencies for function return values
		//TODO: add checks that function inputs match the corresponding function signature
	}
	
	boolean isRAM(Varnode v) {
		return "ram".equals(currentProgram.getLanguage().getAddressFactory().getAddressSpace((int)v.getAddress().getOffset()).getName());
	}
	
	String getRegisterName(Varnode v) {
		return currentProgram.getLanguage().getRegister(v.getAddress(), v.getSize()).getName();
	}
	
	public DITChecker(Program cp, HighFunction func, VmctxOffsetData vmctx, int currentFunctionIndex, NewScript script) {
		this.currentProgram = cp;
		this.currentFunction = func;
		this.vmctx = vmctx;
		this.currentFunctionIndex = currentFunctionIndex;
		this.script = script;
		
		this.tc = new TaintHelper(this, vmctx);
		this.mc = new MemoryHelper(this, vmctx);
	}
	
	public boolean checkAddressTainted(Varnode vn) {
		return mc.checkAddressTainted(vn);
	}
	
	public boolean isTainted(Varnode vn) {
		return tc.isTainted(vn);
	}
	
	public String decomposeAddr(Varnode vn) {
		return mc.decomposeAddr(vn, new HashMap<>());
	}
	
	//attempts to resolve the exact value of a varnode statically
	public long resolveValue(Varnode vn) {
		if(vn.isConstant()) {
			return vn.getOffset();
		} else if (vn.isUnique() || vn.isRegister()) {
			PcodeOp op = vn.getDef();
			if(op.getOpcode() == PcodeOp.COPY) {
				return resolveValue(op.getInput(0));
			}else if(op.getOpcode() == PcodeOp.LOAD) {
				Varnode space = op.getInput(0);
				if(!isRAM(space)) {
					throw new RuntimeException("Attempted to resolve non-RAM load");
				}
				long addr = resolveValue(op.getInput(1));
				
				AddressSpace ram = currentProgram.getLanguage().getAddressFactory().getAddressSpace((int)space.getAddress().getOffset());
				
				try {
					return currentProgram.getMemory().getLong(ram.getAddress(addr));
				} catch (Exception e) {
					throw new RuntimeException("Failed to resolve load to " + ram.getAddress(addr));
				}
			}
		}
		
		throw new RuntimeException("Failed to resolve varnode value");
	}
	
	//given a function entry point, tells you if this function is marked as "trusted"
	public boolean funcIsTrusted(Address entry) {
		for(int i = 0; i < vmctx.functions.length; i++) {
			if(script.getWasmFunction(i).getEntryPoint().equals(entry)) {
				return vmctx.functions[i].trusted;
			}
		}
		throw new RuntimeException("Could not find wasm function at address " + entry);
	}
	
	public void println(String s) {
		script.println(s);
	}
	
	public void print(String s) {
		script.print(s);
	}
	
	public void performChecks() {
		println("Running checks for function " + currentFunctionIndex);
		
		if(vmctx.functions[currentFunctionIndex].trusted) {
			println("Skipping checks since this function is trusted");
			return;
		}
		
		for(DITCheckPass check : checks) {
			println(check.toString() + ": " + (check.check(this)? "PASS": "FAIL"));
		}
	}
}

public class NewScript extends GhidraScript {
	
	private HighFunction decompileFunction(Function f) {
    	DecompileOptions options = new DecompileOptions();
    	DecompInterface ifc = new DecompInterface();
    	ifc.setOptions(options);
    	
    	if (!ifc.openProgram(this.currentProgram)) {
			throw new RuntimeException("Unable to decompile: "+ifc.getLastMessage());
		}
    	
    	ifc.setSimplificationStyle("firstpass");
    	
    	DecompileResults res = ifc.decompileFunction(f, 30, null);
        return res.getHighFunction();
	}
	
	//prints the pcode decompilation of a function within the context of corresponding instructions
	public void printPcodeDump(HighFunction func) {
		Iterator<AddressRange> fiter = func.getFunction().getBody().iterator();
    	
		while(fiter.hasNext()) {
			AddressRange range = fiter.next();
			PseudoDisassembler disassembler = new PseudoDisassembler(currentProgram);

			Address curr = range.getMinAddress();
			while(curr.compareTo(range.getMaxAddress()) < 0) {
				Instruction instr;
				try {
					instr = disassembler.disassemble(curr);

					println(curr.toString() + ": " + instr.toString());
					Iterator<PcodeOpAST> instrOps = func.getPcodeOps(curr);
					while(instrOps.hasNext()){
						println("    " + instrOps.next().toString());
					}

					curr = curr.add(instr.getLength());
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
	}
	
	public Function getWasmFunction(int index) {
		String functionName = "_wasm_function_" + index;
		List<Symbol> functionSymbols = getSymbols("_wasm_function_" + index, null);
		if(functionSymbols.size() != 1) {
			throw new RuntimeException("Conflicting or nonexistent symbols: " + functionName);
		}
		
		Address funcLocation = functionSymbols.get(0).getAddress();
		Function func = getFunctionAt(funcLocation);
		
		return func;
	}

    public void run() throws Exception {
    	
    	Gson gson = new Gson();
    	MemoryBlock vmoffBlock = getMemoryBlock(".vmcontext_offsets");
    	
    	if(vmoffBlock == null) {
    		throw new RuntimeException(".vmcontext_offsets section not found in binary!");
    	}

    	byte[] vmoffData = new byte[(int) vmoffBlock.getSize()];
    	vmoffBlock.getBytes(vmoffBlock.getStart(), vmoffData);
    	
    	VmctxOffsetData vmoffs = gson.fromJson(new String(vmoffData), VmctxOffsetData.class);
    	
    	for(int i = 0; i < vmoffs.functions.length; i++) {
    		Function func = getWasmFunction(i);
    		HighFunction highFunc = decompileFunction(func);
    		
    		DITChecker ditChecker = new DITChecker(currentProgram, highFunc, vmoffs, i, this);
    		ditChecker.performChecks();
    	}
    	
    	
    }

}
