package efidra;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.util.task.TaskMonitor;

public abstract class EFIdraExecutableAnalyzerScript extends GhidraScript {
	
	public abstract boolean canAnalyze(ByteProvider provider);
	
	public abstract void analyzeExecutable(EFIdraExecutableData exe, MessageLog log, TaskMonitor tMonitor);
	
	@Override
	protected void run() throws Exception {
	}

}
