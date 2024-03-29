package efidra;

import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.store.LockException;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.IncompatibleLanguageException;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;

public abstract class EFIdraExecutableAnalyzerScript extends GhidraScript {
	
	protected DecompInterface decompiler = null;
	
	/**
	 * This method should be overridden to determine whether or not this script
	 * can analyze a binary described by the given provider
	 * @param provider The ByteProvider representation of the executable bytes
	 * @return true if this script can analyze the executable, and false
	 * otherwise
	 */
	public abstract boolean canAnalyze(ByteProvider provider);
	
	/**
	 * This method should actually run the analysis on the executable binary 
	 * described by the data stored in exe
	 * @param exe A data store of relevant components of the Program for 
	 * analysis
	 * @param log The log to which information can be written
	 * @param tMonitor The TaskMonitor for this analysis job
	 */
	public abstract void analyzeExecutable(EFIdraExecutableData exe, MessageLog log, 
			TaskMonitor tMonitor);
	
	/**
	 * Decompiles the given function, using the given task monitor, timing out
	 * at the given timeoutSecs. If no decompiler has been initialized, 
	 * initializes a new one for the current program
	 * @param function The function to decompile
	 * @param timeoutSecs The number of seconds after which to time out
	 * @param tMonitor The monitor to use for this job
	 * @return the results from the decompilation of the function
	 */
	protected DecompileResults decompileFunction(Function function, int timeoutSecs, 
			TaskMonitor tMonitor) {
		if (decompiler == null) {
			decompiler = new DecompInterface();
			decompiler.openProgram(currentProgram);
		}
		return decompiler.decompileFunction(function, timeoutSecs, tMonitor);
	}
	
	/**
	 * Decompiles the given function, using the script's task monitor, with no
	 * timeout set. If no decompiler has been initialized, initializes a new 
	 * one for the current program
	 * @param function The function to decompile
	 * @return the results from the decompilation of the function
	 */
	protected DecompileResults decompileFunction(Function function) {
		return decompileFunction(function, 0, monitor);
	}
	
	/**
	 * Initializes the relevant script members (monitor and currentProgram), 
	 * and then calls the analyzeExecutable method, which should be overridden 
	 * to perform the actual analysis on the executable
	 * @param exe A data store of relevant components of the Program for 
	 * analysis
	 * @param log The log to which information can be written
	 * @param tMonitor The TaskMonitor for this analysis job
	 */
	public void initAndAnalyze(EFIdraExecutableData exe, MessageLog log, TaskMonitor tMonitor) {
		monitor = tMonitor;
		currentProgram = exe.parentROM;
		analyzeExecutable(exe, log, tMonitor);
	}
	
	/**
	 * Gets a disassembler for the currentProgram using its language
	 * @return The disassembler for the currentProgram
	 */
	protected Disassembler getDisassembler() {
		return Disassembler.getDisassembler(currentProgram, monitor, DisassemblerMessageListener.CONSOLE);
	}
	
	/**
	 * Gets a disassembler for the program using its language
	 * @param program The program to disassemble
	 * @return The disassembler for the given program
	 */
	protected Disassembler getDisassembler(Program program) {
		return Disassembler.getDisassembler(program, monitor, DisassemblerMessageListener.CONSOLE);
	}
	
//	/**
//	 * Gets a disassembler for the program using the given language
//	 * @param program The program to disassemble
//	 * @param language The language to use for disassembly
//	 * @return The disassembler of the given language for the given program
//	 * @throws IncompatibleLanguageException 
//	 * @throws LockException 
//	 * @throws IllegalStateException 
//	 */
//	protected Disassembler getDisassembler(Program program, Language language) 
//			throws IllegalStateException, LockException, IncompatibleLanguageException {
//		Language oldLang = program.getLanguage();
//		CompilerSpecID csId = program.getCompilerSpec().getCompilerSpecID();
//		program.setLanguage(language, csId, false, monitor);
//		Disassembler dis = Disassembler.getDisassembler(program, monitor, DisassemblerMessageListener.CONSOLE);
//		program.setLanguage(oldLang, csId, false, monitor);
//		return dis;
////		return Disassembler.getDisassembler(language, program.getAddressFactory(), monitor, DisassemblerMessageListener.CONSOLE);
//	}
	
	/**
	 * Gets the first language which matches the given processor, word size,
	 * and variant 
	 * @param processor The processor type of the language
	 * @param size The word size (should be 32 for 32-bit or 64 for 64-bit)
	 * @param variant The variant of the language
	 * @return The first language found which matches the processor, size, and
	 * variant
	 * @throws LanguageNotFoundException If no matching language can be found
	 */
	protected Language getLanguage(Processor processor, int size, String variant) 
			throws LanguageNotFoundException {
		List<LanguageDescription> langDescs = 
				DefaultLanguageService.getLanguageService().getLanguageDescriptions(processor);
		for (LanguageDescription langDesc : langDescs) {
			if (langDesc.getEndian().isBigEndian()) {
				// UEFI does not support big endian
				continue;
			}
			if (langDesc.getSize() == 16) {
				// UEFI does not support 16 bit
				continue;
			}
			if (size != 0 && langDesc.getSize() != size) {
				// size is given, need to find a language that matches
				continue;
			}
			if (variant != null && !variant.equals(langDesc.getVariant())) {
				// variant is given, need to find a language that matches
				continue;
			}
			return getLanguage(langDesc.getLanguageID());
		}
		throw new LanguageNotFoundException(processor);
	}
	
	/**
	 * Gets the first language which matches the given processor and word size 
	 * @param processor The processor type of the language
	 * @param size The word size (should be 32 for 32-bit or 64 for 64-bit)
	 * @return The first language found which matches the processor and size
	 * @throws LanguageNotFoundException If no matching language can be found
	 */
	protected Language getLanguage(Processor processor, int size) 
			throws LanguageNotFoundException {
		return getLanguage(processor, size, null);
	}
	
	/**
	 * Gets the first language which matches the given processor and variant 
	 * @param processor The processor type of the language
	 * @param variant The variant of the language
	 * @return The first language found which matches the processor and variant
	 * @throws LanguageNotFoundException If no matching language can be found
	 */
	protected Language getLanguage(Processor processor, String variant) 
			throws LanguageNotFoundException {
		return getLanguage(processor, 0, variant);
	}
	
	/**
	 * Gets the first language which matches the given processor, word size,
	 * and variant 
	 * @param processor The name of the processor type of the language
	 * @param size The word size (should be 32 for 32-bit or 64 for 64-bit)
	 * @param variant The variant of the language
	 * @return The first language found which matches the processor, size, and
	 * variant
	 * @throws LanguageNotFoundException If no matching language can be found
	 */
	protected Language getLanguage(String processor, int size, String variant) 
			throws LanguageNotFoundException {
		return getLanguage(Processor.toProcessor(processor), size, variant);
	}
	
	/**
	 * Gets the first language which matches the given processor and word size 
	 * @param processor The name of the processor type of the language
	 * @param size The word size (should be 32 for 32-bit or 64 for 64-bit)
	 * @return The first language found which matches the processor and size
	 * @throws LanguageNotFoundException If no matching language can be found
	 */
	protected Language getLanguage(String processor, int size) 
			throws LanguageNotFoundException {
		return getLanguage(processor, size, null);
	}
	
	/**
	 * Gets the first language which matches the given processor and variant 
	 * @param processor The name of the processor type of the language
	 * @param variant The variant of the language
	 * @return The first language found which matches the processor and variant
	 * @throws LanguageNotFoundException If no matching language can be found
	 */
	protected Language getLanguage(String processor, String variant) 
			throws LanguageNotFoundException {
		return getLanguage(processor, 0, variant);
	}
	
	@Override
	protected void run() throws Exception {
	}

}
