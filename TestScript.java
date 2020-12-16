//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.pcode.emulate.BreakTable;
import ghidra.pcode.emulate.BreakTableCallBack;
import ghidra.pcode.emulate.Emulate;
import ghidra.pcode.emulate.InstructionDecodeException;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.model.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.TreeSet;

import ghidra.app.emulator.*;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;

public class TestScript extends GhidraScript {
	
	private static final int MAX_INSTR_LENGTH = 8;

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
		LDST, //this address of the destination cannot be a tainted value but the value being loaded/stored can be tainted
		NONDIT, //this instruction may not read any tainted value
	}
	
	class MemTaintTracker extends MemoryAccessFilter {
		
		//represents a single byte which was accessed, one optimization would be to represent ranges rather than bytes
		public class AccessLocation implements Comparable<AccessLocation> {
			AddressSpace space;
			long offset;
			
			public AccessLocation(AddressSpace spc, long off) {
				this.space = spc;
				this.offset = off;
			}
			
			@Override
			public int compareTo(TestScript.MemTaintTracker.AccessLocation o) {
				int cmpSpc = this.space.compareTo(o.space);
				if(cmpSpc != 0) return cmpSpc;
				
				int cmpOff = Long.compare(this.offset, o.offset);
				if(cmpOff != 0) return cmpOff;
				
				return 0;
			}
			
			@Override
			public String toString() {
				return space.toString() + "(" + Long.toString(offset, 16) + ")";
			}
		}
		
		TreeSet<AccessLocation> taintSet = new TreeSet<>(); //may contain secret-dependent values
		boolean tainted = false; //whether the current executing instruction has been tainted yet
		InstrType currInstrType = InstrType.NONDIT; //whether this instruction is a DIT instruction
		boolean ditViolationDetected = false;
		boolean raiseDitViolations = true;
		
		public void beginInstr(InstrType instrType) {
			this.currInstrType = instrType;
			this.tainted = false;
			// A DIT instruction cannot raise DIT violations 
			// And LD/ST instructions cannot raise DIT violations outside of the target address being tainted
			this.raiseDitViolations = instrType == InstrType.NONDIT;
		}
		
		//marks the entirety of the accessed range as tainted
		public void taint(AddressSpace spc, long off, int size) {
			for(int i = 0; i < size; i++) {
				taintSet.add(new AccessLocation(spc, off + i));
			}
		}
		
		//marks the entirety of the accessed range as untainted
		public void untaint(AddressSpace spc, long off, int size) {
			for(int i = 0; i < size; i++) {
				taintSet.remove(new AccessLocation(spc, off + i));
			}
		}
		
		//returns true if any part of this read has been tainted
		public boolean checkTaint(AddressSpace spc, long off, int size) {
			for(int i = 0; i < size; i++) {
				if(taintSet.contains(new AccessLocation(spc, off + i))) {
					return true;
				}
			}
			return false;
		}
		
		//allows an instruction to be temporarily treated as DIT or non-DIT
		public void setRaiseDitViolations(boolean rdv) {
			this.raiseDitViolations = rdv;
		}

		@Override
		protected void processRead(AddressSpace spc, long off, int size, byte[] values) {
			boolean readTainted = checkTaint(spc, off, size);

			if(readTainted) {
				if(!this.tainted) {
					this.tainted = true;
				}
				
				if(this.raiseDitViolations && this.currInstrType != InstrType.DIT) {
					println("DIT VIOLATION");
					ditViolationDetected = true;
				}
			}
			
			printf("read  %s %x (%d) %d\n", spc.toString(), off, size, this.tainted? 1: 0);
		}

		@Override
		protected void processWrite(AddressSpace spc, long off, int size, byte[] values) {
			printf("write %s %x (%d) %d\n", spc.toString(), off, size, this.tainted? 1: 0);
			if(this.tainted) {
				this.taint(spc, off, size);
			}else {
				this.untaint(spc, off, size);
			}
		}
	}
	
	class DitEmulator extends Emulate {
		
		AddressFactory addrFactory;
		MemoryState memstate;
		MemTaintTracker taintTrack;
		
		public DitEmulator(SleighLanguage lang, MemoryState s, BreakTable b, MemTaintTracker tt) {
			super(lang, s, b);
			
			addrFactory = lang.getAddressFactory();
			memstate = s;
			taintTrack = tt;
		}
		
		@Override
		public void executeInstruction(boolean stopAtBreakpoint, TaskMonitor monitor1) throws CancelledException, LowlevelError, InstructionDecodeException {
    		Address pcAddr = this.getExecuteAddress();
    		printf("PC: %x\n", pcAddr.getOffset());
    		
    		byte[] instrBytes = new byte[MAX_INSTR_LENGTH];
    		
    		memstate.getChunk(instrBytes, pcAddr.getAddressSpace(), pcAddr.getOffset(), MAX_INSTR_LENGTH, false);
    		
    		Instruction instr;
			try {
				instr = new PseudoDisassembler(currentProgram).disassemble(this.getExecuteAddress(), instrBytes);
			} catch (Exception e) {
				throw new InstructionDecodeException("Failed to disassemble instruction to determine DIT status", this.getExecuteAddress());
			}
    		
    		println(instr.getMnemonicString());
    		InstrType instrType = InstrType.NONDIT;
    		if(DIT_GP_MNEMONICS.contains(instr.getMnemonicString().toUpperCase())) {
    			instrType = InstrType.DIT;
    		}else if(LDST_MNEMONICS.contains(instr.getMnemonicString().toUpperCase())) {
    			instrType = InstrType.LDST;
        		println("here");
    		}
    		
    		taintTrack.beginInstr(instrType);
			
			super.executeInstruction(stopAtBreakpoint, monitor1);
		}
		
		
		// we must override the load and store pcode ops since the ARM manual is specific that loads/stores are DIT wrt the values being loaded/stored
		@Override
		public void executeLoad(PcodeOpRaw op) {

			//we must ensure that the target address is not secret-dependent
			if(taintTrack.currInstrType == InstrType.LDST) {
				taintTrack.setRaiseDitViolations(true);
			}
			
			AddressSpace space =
				addrFactory.getAddressSpace((int) op.getInput(0).getAddress().getOffset()); // Space to read from

			long offset = memstate.getValue(op.getInput(1)); // Offset to read from
			long byteOffset =
				space.truncateAddressableWordOffset(offset) * space.getAddressableUnitSize();
			
			if(taintTrack.currInstrType == InstrType.LDST) {
				taintTrack.setRaiseDitViolations(false);
			}

			Varnode outvar = op.getOutput();
			if (outvar.getSize() > 8) {
				BigInteger res =
					memstate.getBigInteger(space, byteOffset, op.getOutput().getSize(), false);
				memstate.setValue(outvar, res);
			}
			else {
				long res = memstate.getValue(space, byteOffset, op.getOutput().getSize());
				memstate.setValue(op.getOutput(), res);
			}
		}
		
		// we must override the load and store pcode ops since the ARM manual is specific that loads/stores are DIT wrt the values being loaded/stored
		@Override
		public void executeStore(PcodeOpRaw op) {
			
			//we must ensure that the target address is not secret-dependent
			if(taintTrack.currInstrType == InstrType.LDST) {
				taintTrack.setRaiseDitViolations(true);
			}
			
			AddressSpace space =
				addrFactory.getAddressSpace((int) op.getInput(0).getAddress().getOffset()); // Space to store in

			long offset = memstate.getValue(op.getInput(1)); // Offset to store at
			long byteOffset =
				space.truncateAddressableWordOffset(offset) * space.getAddressableUnitSize();

			if(taintTrack.currInstrType == InstrType.LDST) {
				taintTrack.setRaiseDitViolations(false);
			}
			
			taintTrack.setRaiseDitViolations(false);
			Varnode storedVar = op.getInput(2); // Value being stored
			if (storedVar.getSize() > 8) {
				BigInteger val = memstate.getBigInteger(storedVar, false);
				memstate.setValue(space, byteOffset, op.getInput(2).getSize(), val);
			}
			else {
				long val = memstate.getValue(storedVar);
				memstate.setValue(space, byteOffset, op.getInput(2).getSize(), val);
			}
		}
	}

    public void run() throws Exception {
    	if(currentProgram == null) {
    		printerr("Please open a program you would like to verify.");
    		return;
    	}
    	
    	if (!"AARCH64:LE:64:v8A".equals(currentProgram.getLanguageID().toString())) {
    		printerr("Sorry, this PoC script is currently only designed to run for AArch64.");
    		return;
    	}
    	
    	if(currentAddress == null) {
    		printerr("Please place your cursor at the beginning of a function you would like to verify.");
    		return;
    	}

    	EmulatorHelper emuHelper = new EmulatorHelper(currentProgram);
    	SleighLanguage language = (SleighLanguage)currentProgram.getLanguage();
    	MemTaintTracker taintTrack = new MemTaintTracker();
    	Emulator emu = emuHelper.getEmulator();
    	emuHelper.writeRegister(emuHelper.getPCRegister(), currentAddress.getOffset());
    	emuHelper.writeRegister(emuHelper.getStackPointerRegister(), 0x000000002FFF0000);
    	emuHelper.writeRegister("x0", 0x420000);
    	emuHelper.writeRegister("x1", 42);
    	Address taintedRegAddr = emuHelper.getLanguage().getRegister("x1").getAddress();
    	taintTrack.taint(taintedRegAddr.getAddressSpace(), taintedRegAddr.getOffset(), taintedRegAddr.getSize());

    	taintTrack.setFilterOnExecutionOnly(false);

    	emu.addMemoryAccessFilter(taintTrack);
    	MemoryState memState = emuHelper.getEmulator().getFilteredMemState();
    	
    	println(Long.toString(memState.getValue(emuHelper.getPCRegister())));
    	
    	DitEmulator ditEmu = new DitEmulator(language, memState, new BreakTableCallBack(language), taintTrack);
    	ditEmu.setExecuteAddress(currentAddress);
    	
    	println(currentAddress.toString());
    	
    	while(true) {
    		if(ditEmu.getExecuteAddress().getOffset() == 0) {
    			println("Successfully finished emulating function with no DIT violations detected.");
    			break;
    		}
    		
    		ditEmu.executeInstruction(false, monitor);
    		
    		if(taintTrack.ditViolationDetected) {
    			break;
    		}
    	}
    	
    	printf("value of r0 after function call: %x\n", emuHelper.readRegister("x0"));
    	println(taintTrack.taintSet.toString());
    	
    	emuHelper.dispose();
    }

}
