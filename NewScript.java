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
import ghidra.program.model.lang.Register;

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
	
	public boolean checkInitialTaint(Address addr, int len) {
		if(main.contains(main.getRegister("sp"), addr, len)) {
			return false;
		}
		if(main.contains(main.getRegister("x30"), addr, len)) {
			return false;
		}
		
		int funcIndex = main.currentFunctionIndex;
		boolean[] paramSecrecy = vmctx.functions[funcIndex].paramSecrecy;
		
		//the first 7 arguments are passed in through x2-x8
		for(int i = 0; i <= 6 && i < paramSecrecy.length; i++) {
			if(main.contains(main.getRegister("x" + (2 + i)), addr, len)) {
				return paramSecrecy[i];
			}
		}
		
		throw new RuntimeException("Cannot determine initial taintedness of: " + addr);
	}
	
	public boolean checkInitialTaint(Register reg) {
		if(reg.getLeastSignificantBit() != 0 || reg.getBitLength() % 8 != 0) {
			throw new RuntimeException(reg + " isn't byte-aligned, can't determine initial taint");
		}
		
		return checkInitialTaint(reg.getAddress(), reg.getBitLength() / 8);
	}
	
	//checks if an initial Varnode (one with no source) is tainted
	public boolean checkInitialTaint(Varnode vn) {
		if(vn.getDef() != null) {
			throw new IllegalArgumentException("Varnode must be initial");
		}
		if(!vn.isRegister()) {
			throw new IllegalArgumentException("Varnode must be a register");
		}
		
		return checkInitialTaint(vn.getAddress(), vn.getSize());
	}
	
	//returns false if we are sure that the register is not tainted immediately prior to op
	public boolean checkRegisterTaint(Register reg, PcodeOp op, HashSet<PcodeOp> visited) {
		if(visited.contains(op)) {
			return false; //the other branch will catch the taint we are looking for
		}
		
		visited.add(op);
		
		List<PcodeOp> predecessors = main.getPredecessors(op);
		if(predecessors.size() == 0) {
			return checkInitialTaint(reg);
		}
		boolean res = false;
		for(PcodeOp pred: predecessors) {
			Varnode output = pred.getOutput();
			if(output != null && output.isRegister()) {
				Register outputReg = main.getRegister(output);
				if(main.intersect(reg, outputReg)) {
					if(outputReg.contains(reg)) {
						res |= main.isTainted(output);
						continue;
					}else if(reg.contains(outputReg)) {
						res |= main.isTainted(output);
						res |= checkRegisterTaint(reg, pred, visited);
						continue;
					}
					throw new RuntimeException("output register " + outputReg + " intersects " + reg + " but does not contain it -- cannot determine taintedness");
				}
			}
			res |= checkRegisterTaint(reg, pred, visited);
		}
		return res;
	}
	
	//returns false if we are sure the value is not tainted, true otherwise
	private boolean checkIsTainted(Varnode vn, HashSet<Varnode> visited) {
		boolean res = false;
		
		if(visited.contains(vn)) { // cycle detected, but we are able to determine the true taintedness from the other branch
			return false;
		}
		visited.add(vn);
		
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
					throw new RuntimeException("Unhandled load target: " + op.getInput(0).toString() + " at " + main.getPcodeOpLocation(op));
				}
				return main.memLocationTainted(op.getInput(1), op);
			}else {
				Iterator<PcodeOp> ops = op.getParent().getIterator();
				throw new RuntimeException("Unhandled pcode op: " + op.toString() + " at " + main.getPcodeOpLocation(op));
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

	ArrayList<ASTNode> secretAddresses; // a load from this address will yield a tainted value and a store may be tainted
	ArrayList<ASTNode> publicAddresses; // a load from this address will yield an untainted value and a store must be untainted
	ArrayList<ASTNode> pointerAddresses; // a load from this address will yield a pointer, which is neither tainted nor untainted
	//this prevents arithmetic from being done on a pointer, or subtracting a pointer to itself to add another pointer, etc.
	//since calling isTainted() on a varnode that evaluates to it will lead to an exception
	
	ASTNode stack = new AnyOffset(new RegisterNode("sp"));

	public MemoryHelper(DITChecker m, VmctxOffsetData vmctx) {
		this.main = m;
		secretAddresses = new ArrayList<>();
		publicAddresses = new ArrayList<>();
		pointerAddresses = new ArrayList<>();
		
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
			pointerAddresses.add(firstPtr);
			ASTNode secondPtr = new Load(firstPtr);
			pointerAddresses.add(secondPtr);
			
	    	ASTNode finalLevel = new AnyOffset(new Load(secondPtr));
	    	if(vmctx.memories[i].secret) {
	    		secretAddresses.add(finalLevel);
	    	}else {
	    		publicAddresses.add(finalLevel);
	    	}
		}
	}
	
	interface ASTNode {
		//matches is designed to be conservative -- if it returns true, we are sure the varnode matches the description
		//if it returns false, this doesn't mean the varnode couldn't match the description, just that we're not sure
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
			}else if(op.getOpcode() == PcodeOp.INT_SUB) {
				Varnode left = op.getInput(0);
				Varnode right = op.getInput(1);
				if(right.isConstant()) {
					return new SpecificOffset(base, offset + right.getOffset()).matches(left);
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
					return registerName.equals(main.getRegister(v).getName());
				}
				return false;
			}else if(op.getOpcode() == PcodeOp.COPY) {
				return matches(op.getInput(0));
			}
			
			return false;
		}
	}
	
	class StackSlot {
		long offset;
		int size;
		
		public StackSlot(long o, int s) {
			this.offset = o;
			this.size = s;
		}
		
		@Override
		public String toString() {
			return size + "@(sp + " + offset + ")";
		}
		
		public boolean intersects(StackSlot o) {
			return (this.offset < o.offset + o.size) && (o.offset < this.offset + this.size);
		}
		
		public boolean covers(StackSlot o) {
			return (o.offset >= this.offset) && (o.offset + o.size <= this.offset + this.size);
		}
	}
	
	public StackSlot resolveStackSlot(Varnode v, int size) {
		if(!stack.matches(v)) {
			throw new RuntimeException("Attempted to flatten non-stack address");
		}
		PcodeOp op = v.getDef();
		if(op == null) {
			if(!v.isRegister() || !main.getRegister(v).getName().equals("sp")) {
				throw new RuntimeException("Failed to flatten: expected stack pointer, got " + v);
			}
			return new StackSlot(0, size);
		}else if(op.getOpcode() == PcodeOp.COPY) {
			return resolveStackSlot(op.getInput(0), size);
		}else if(op.getOpcode() == PcodeOp.INT_ADD) {
			StackSlot lhs = resolveStackSlot(op.getInput(0), size);
			lhs.offset += main.resolveValue(op.getInput(1));
			return lhs;
		}else if(op.getOpcode() == PcodeOp.INT_SUB) {
			StackSlot lhs = resolveStackSlot(op.getInput(0), size);
			lhs.offset -= main.resolveValue(op.getInput(1));
			return lhs;
		}else {
			throw new RuntimeException("Could not handle op " + op + " at " + main.getPcodeOpLocation(op) + " when attempting to flatten stack address");
		}
	}
	
	//checks if a stack slot is tainted at the start of the function
	private boolean initialStackSlotIsTainted(StackSlot slot) {
		FunctionsVmctxData function = main.vmctx.functions[main.currentFunctionIndex];
		//all arguments after 6 are allocated a stack slot above the current frame
		for(int i = 6; i < function.paramSecrecy.length; i++) {
			StackSlot paramSlot = new StackSlot(8 * (i - 6), 8);
			if(paramSlot.covers(slot)) {
				return function.paramSecrecy[i];
			}
		}
		throw new RuntimeException("Cannot determine taint of stack slot " + slot + " at start of function");
	}

	//determines whether or not the stack slot being referred to by toAddr could contain a tainted value immediately prior to when op runs
	private boolean stackSlotContainsTaint(StackSlot toAddr, PcodeOp op, HashSet<PcodeOp> visited) {
		if(visited.contains(op)) {
			return false; //the other branch will catch the taint we are looking for
		}
		
		visited.add(op);

		boolean res = false;

		List<PcodeOp> predecessors = main.getPredecessors(op);
		if(predecessors.size() == 0) {
			return initialStackSlotIsTainted(toAddr);
		}
		for(PcodeOp pred : predecessors) {
			if(pred.getOpcode() == PcodeOp.STORE && stack.matches(pred.getInput(1))) {
				//the predecessor is writing to the stack
				StackSlot dest = resolveStackSlot(pred.getInput(1), pred.getInput(2).getSize());
				if(dest.intersects(toAddr)) {
					if(dest.covers(toAddr)) {
						//the predecessor has overwritten our stack slot
						res |= main.isTainted(pred.getInput(2));
						continue; //since the stack slot was overwritten, we no longer need to continue tracing backwards
					}
					throw new RuntimeException("Store intersects stack slot but does not cover it: " + dest + " (stack slot " + toAddr + ")");
				}
			}
			res |= stackSlotContainsTaint(toAddr, pred, visited);
		}
		
		return res;
	}
	
	public boolean stackSlotContainsTaint(StackSlot toAddr, PcodeOp op) {
		return stackSlotContainsTaint(toAddr, op, new HashSet<>());
	}
	
	//op is the load/store operation being performed
	//vn is the address being loaded/stored to
	//return true if the varnode, when interpreted as an address, points to a location that could contain a secret value
	public boolean memLocationTainted(Varnode vn, PcodeOp op) {
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
			if(op.getOpcode() == PcodeOp.STORE) {
				return true; //both secret and public values are allowed to be stored on the stack
			}else if(op.getOpcode() == PcodeOp.LOAD) {
				StackSlot stackOff = resolveStackSlot(vn, op.getOutput().getSize());
				return stackSlotContainsTaint(stackOff, op);
			}else {
				throw new RuntimeException("Invalid pcode op given to memLocationTainted");
			}
		}
		
		throw new RuntimeException("Cannot resolve address: " + toASTString(vn, new HashMap<>()));
	}
	
	public boolean addrWellFormed(Varnode vn) {
		for(ASTNode secretAddr : secretAddresses) {
			if(secretAddr.matches(vn)) {
				return true;
			}
		}
		for(ASTNode publicAddr : publicAddresses) {
			if(publicAddr.matches(vn)) {
				return true;
			}
		}
		for(ASTNode pointer : pointerAddresses) {
			if(pointer.matches(vn)) {
				return true;
			}
		}
		if(stack.matches(vn)) return true;
		return false;
	}
	
	int nextIdxForDecomposition = 0;
	public String toASTString(Varnode vn, HashMap<Varnode, Integer> visited) {
		if(visited.containsKey(vn)) {
			return String.format("(%d)", visited.get(vn));
		}
		
		StringBuilder res = new StringBuilder();
		
		visited.put(vn, nextIdxForDecomposition++);
		res.append(String.format("%d: ", visited.get(vn)));
		
		if(vn.isRegister() || vn.isUnique()) {
			PcodeOp op = vn.getDef();
			
			if(op == null) {
				res.append(vn.toString(main.currentProgram.getLanguage()));
				return res.toString();
			}
			
			if(op.getOpcode() == PcodeOp.COPY) {
				res.append(toASTString(op.getInput(0), visited));
				return res.toString();
			}
			
			res.append(op.getMnemonic());

			res.append(" ( ");
			
			for(int i = 0; i < op.getNumInputs(); i++) {
				res.append(toASTString(op.getInput(i), visited));
				res.append(", ");
			}
			
			res.append(" ) ");
		}else {
			res.append(vn.toString());
		}
		
		return res.toString();
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("Secret addresses: " + secretAddresses + "\n");
		sb.append("Public addresses: " + publicAddresses + "\n");
		sb.append("Stack addresses: " + stack + "\n");
		return sb.toString();
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
					try {
						if(main.isTainted(input)) {
							main.println("Input " + input.toString(main.currentProgram.getLanguage()) + " is tainted at " + instr.getAddress().toString());
							return false;
						}
					}catch(RuntimeException e) {
						main.println("Failed to check taint of " + input + ", used in instruction at " + instr.getAddress());
						throw e;
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
			try {
				if(!main.memLocationTainted(addr, op)) {
					// we are storing to a public location
					try {
						if(main.isTainted(toStore)) {
							main.println("At pcode op " + op + " at " + main.getPcodeOpLocation(op));
							main.println("We are storing to the address " + main.toASTString(addr) + ", which is public, "
									+ "but we are writing the value " + toStore + ", which is tainted");
							return false;
						}
					}catch(RuntimeException e) {
						main.println("Failed to check taint of " + toStore + 
								" at " + main.getPcodeOpLocation(op));
						throw e;
					}
				}
			}catch(RuntimeException e) {
				main.println("When analyzing op " + op + " at " + main.getPcodeOpLocation(op));
				throw e;
			}
		}
		
		return true;
	}
}

class TaintedAddrCheckPass implements DITCheckPass {
	public String toString() {
		return "Check that target addresses of loads/stores are not secret-dependent and fit expectations";
	}

	@Override
	public boolean check(DITChecker main) {
		HighFunction func = main.currentFunction;
		Iterator<PcodeOpAST> ops = func.getPcodeOps();
		
		while(ops.hasNext()) {
			PcodeOpAST op = ops.next();
			
			if(op.getOpcode() != PcodeOp.STORE && op.getOpcode() != PcodeOp.LOAD) continue;
			
			Varnode addr = op.getInput(1);
			
			try {
				if(!main.addrWellFormed(addr)) {
					main.println("We found a load/store to the address " + main.toASTString(addr) + ", which does not match any expected format.");
					main.println(main.mc.toString());
					return false;
				}
			}catch(RuntimeException e) {
				main.println("When analyzing op " + op + " at " + main.getPcodeOpLocation(op));
				main.println(main.toASTString(addr));

				for(Register r : main.currentProgram.getLanguage().getRegisters()) {
					main.println(r.toString() + ": " + r.getAddress().toString());
				}
				
				throw e;
			}
		}
		
		return true;
	}
}

class FunctionCallPass implements DITCheckPass {
	public String toString() {
		return "Check that a trusted function is never called by an untrusted function, and that a tainted value is never passed as public";
	}
	
	//returns the first pcode op in the set of INDIRECT ops preceeding the call op
	private PcodeOp skipIndirectOps(DITChecker main, PcodeOp callOp) {
		PcodeOp walker = callOp;
		while(true) {
			List<PcodeOp> predecessors = main.getPredecessors(walker);
			if(predecessors.size() != 1) return walker;
			
			PcodeOp prev = predecessors.get(0);
			if(prev.getOpcode() != PcodeOp.INDIRECT) return walker;
			
			int iop = (int)prev.getInput(1).getOffset();
			SequenceNumber seq = new SequenceNumber(main.getPcodeOpLocation(callOp), iop);
			if(!main.currentFunction.getPcodeOp(seq).equals(callOp)) return walker;
			
			walker = prev;
		}
	}
	
	private boolean checkFunctionCall(DITChecker main, int functionIndex, PcodeOp callOp) {
		FunctionsVmctxData function = main.vmctx.functions[functionIndex];
		if(function.trusted) {
			main.println("We found a call from untrusted function " + main.currentFunctionIndex 
					+ " to trusted function " + functionIndex + " occuring at " + main.getPcodeOpLocation(callOp));
			return false;
		}
		
		try {
			for(int i = 0; i < function.paramSecrecy.length; i++) {
				if(!function.paramSecrecy[i]) {
					if(i >= 6) {
						main.println("Warning: skipped check for " 
								+ i + "th parameter secrecy for function call at " + main.getPcodeOpLocation(callOp));
						continue;
					}
					Register paramReg = main.getRegister("x" + (i + 2)); // the first 6 arguments are passed in through [x2, x8)
					PcodeOp startOp = skipIndirectOps(main, callOp);
					if(main.checkRegisterTaint(paramReg, startOp)) {
						main.println("At " + main.getPcodeOpLocation(callOp) + 
								", the " + i + "th argument to the function should be public but was determined to be tainted");
						return false;
					}
				}
			}
		}catch(RuntimeException e) {
			main.println("Error when checking function call at " + main.getPcodeOpLocation(callOp));
			throw e;
		}
		
		return true;
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
				
				int targetFuncIndex = main.indexOfFunctionAt(targetFunc.getEntryPoint());
				
				return checkFunctionCall(main, targetFuncIndex, op);
			}else if(opcode == PcodeOp.CALLIND || opcode == PcodeOp.BRANCHIND) {
				long destOff = main.resolveValue(op.getInput(0));
				AddressSpace currentAddressSpace = main.currentFunction.getFunction().getEntryPoint().getAddressSpace();
				Address targetAddr = currentAddressSpace.getAddress(destOff);
				int targetFuncIndex = main.indexOfFunctionAt(targetAddr);
				
				return checkFunctionCall(main, targetFuncIndex, op);
			}
		}

		return true;
	}
}

//encapsulates everything needed to verify a single function
class DITChecker {
	NewScript script;
	VmctxOffsetData vmctx;
	Program currentProgram;
	TaintHelper tc;
	MemoryHelper mc;
	HighFunction currentFunction;
	int currentFunctionIndex = -1;
	HashMap<PcodeOp, Address> allOps; //this maps each pcode op to the address where it's located
	
	ArrayList<DITCheckPass> checks = new ArrayList<>();
	{
		checks.add(new NonDITInstrCheckPass());
		checks.add(new TaintedAddrCheckPass());
		checks.add(new SecretStoresCheckPass());
		checks.add(new FunctionCallPass());
		//TODO: add data dependencies for function return values
	}
	
	boolean isRAM(Varnode v) {
		return "ram".equals(currentProgram.getLanguage().getAddressFactory().getAddressSpace((int)v.getAddress().getOffset()).getName());
	}
	
	Register getRegister(Varnode v) {
		if(!v.isRegister()) {
			throw new IllegalArgumentException("Varnode must be register");
		}
		return currentProgram.getLanguage().getRegister(v.getAddress(), v.getSize());
	}
	
	String prettyPrint(Varnode v) {
		if(v.isRegister()) {
			return getRegister(v).getName();
		}
		return v.toString();
	}
	
	public DITChecker(Program cp, HighFunction func, VmctxOffsetData vmctx, int currentFunctionIndex, NewScript script) {
		this.currentProgram = cp;
		this.currentFunction = func;
		this.vmctx = vmctx;
		this.currentFunctionIndex = currentFunctionIndex;
		this.script = script;
		
		this.tc = new TaintHelper(this, vmctx);
		this.mc = new MemoryHelper(this, vmctx);
		
		this.allOps = new HashMap<>();
		Iterator<AddressRange> addressRanges = func.getFunction().getBody().iterator();
		while(addressRanges.hasNext()) {
			Iterator<Address> range = addressRanges.next().iterator();
			while(range.hasNext()) {
				Address addr = range.next();
				Iterator<PcodeOpAST> ops = func.getPcodeOps(addr);
				while(ops.hasNext()) {
					allOps.put(ops.next(), addr);
				}
			}
		}
	}
	
	public Address getPcodeOpLocation(PcodeOp op) {
		return allOps.getOrDefault(op, null);
	}
	
	public boolean memLocationTainted(Varnode vn, PcodeOp loadOp) {
		return mc.memLocationTainted(vn, loadOp);
	}
	
	public boolean addrWellFormed(Varnode vn) {
		return mc.addrWellFormed(vn);
	}
	
	public boolean isTainted(Varnode vn) {
		return tc.isTainted(vn);
	}
	
	public boolean checkRegisterTaint(Register reg, PcodeOp op) {
		return tc.checkRegisterTaint(reg, op, new HashSet<>());
	}
	
	public String toASTString(Varnode vn) {
		mc.nextIdxForDecomposition = 0;
		return mc.toASTString(vn, new HashMap<>());
	}
	
	//get the pcode op's that may have executed before the current one
	public List<PcodeOp> getPredecessors(PcodeOp op) {
		ArrayList<PcodeOp> res = new ArrayList<>();

		PcodeBlockBasic block = op.getParent();
		SequenceNumber seqnum = op.getSeqnum();
		if(seqnum.getOrder() != 0) { 
			//since this is a basic block, the only possible predecessor is the one preceeding this one in the block
			Iterator<PcodeOp> ops = block.getIterator();
			PcodeOp prev = null, next = null;
			for(int i = 0; i <= seqnum.getOrder(); i++) {
				prev = next;
				next = ops.next();
			}

			assert(next.equals(op));
			assert(prev != null);

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
	
	public Register getRegister(String name) {
		return currentProgram.getLanguage().getRegister(name);
	}
	
	public boolean intersect(Register a, Register b) {
		long a1 = a.getOffset() * 8 + a.getLeastSignificantBit();
		long b1 = b.getOffset() * 8 + b.getLeastSignificantBit();
		long a2 = a1 + a.getBitLength();
		long b2 = b1 + b.getBitLength();
		
		return a1 < b2 && b1 < a2;
	}
	
	public boolean contains(Register a, Address b, int bLen) {
		if(a.getBitLength() % 8 != 0 || a.getLeastSignificantBit() != 0) {
			throw new RuntimeException("Register " + a.toString() + " is not byte-aligned, cannot determine if it contains " + b.toString());
		}
		
		return a.getAddressSpace().equals(b.getAddressSpace())
				&& a.getOffset() <= b.getOffset()
				&& a.getOffset() + a.getBitLength() / 8 >= b.getOffset() + bLen;
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
	
	//returns the function index for the function given its entry point
	public int indexOfFunctionAt(Address entry) {
		for(int i = 0; i < vmctx.functions.length; i++) {
			if(script.getWasmFunction(i).getEntryPoint().equals(entry)) {
				return i;
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
	
	public boolean performChecks() {
		println("Running checks for function " + currentFunctionIndex + " at " + currentFunction.getFunction().getEntryPoint());
		
		if(vmctx.functions[currentFunctionIndex].trusted) {
			println("Skipping checks since this function is trusted");
			return true;
		}
		
		boolean res = true;
		for(DITCheckPass check : checks) {
			try {
				boolean subRes = check.check(this);
				println("\t" + check.toString() + ": " + (subRes? "PASS": "FAIL"));
				res &= subRes;
			}catch(Exception e) {
				println(check.toString() + ": " + "EXCEPT");
				e.printStackTrace();
				res = false;
			}
		}
		
		return res;
	}
}

public class NewScript extends GhidraScript {
	
	private HighFunction decompileFunction(Function f) {
    	DecompileOptions options = new DecompileOptions();
    	options.setWARNCommentIncluded(true);
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
    	
    	boolean result = true;
    	for(int i = 0; i < vmoffs.functions.length; i++) {
    		Function func = getWasmFunction(i);
    		HighFunction highFunc = decompileFunction(func);
    		
    		DITChecker ditChecker = new DITChecker(currentProgram, highFunc, vmoffs, i, this);
    		result &= ditChecker.performChecks();
    	}
    	
    	if(result) {
    		println("VERDICT: Program admitted");
    	}else {
    		println("VERDICT: Program rejected");
    	}
    }

}
