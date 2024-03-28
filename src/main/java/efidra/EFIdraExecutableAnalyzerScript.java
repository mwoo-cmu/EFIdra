package efidra;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Function;
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
	
	@Override
	protected void run() throws Exception {
	}

}
