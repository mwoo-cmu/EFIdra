package efidra;

import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.symbol.Namespace;

public class EFIdraExecutableData {
	public String name;
	public Address baseAddr;
	public Namespace namespace;
	public ProgramModule programTree;
	public ByteProvider provider;
	public Program parentROM;
	
	public EFIdraExecutableData(String name, Address baseAddr, Namespace namespace,
			ProgramModule programTree, ByteProvider provider, Program parentROM) {
		this.name = name;
		this.baseAddr = baseAddr;
		this.namespace = namespace;
		this.programTree = programTree;
		this.provider = provider;
		this.parentROM = parentROM;
	}
}
