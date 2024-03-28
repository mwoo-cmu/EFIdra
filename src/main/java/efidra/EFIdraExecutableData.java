package efidra;

import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.symbol.Namespace;

/**
 * A class which represents the relevant data about an executable from a UEFI
 * ROM, with the following members:
 * 
 * @member name - the name of the executable
 * 
 * @member baseAddr - the base (starting) address of the executable
 * 
 * @member namespace - the Ghidra namespace created for this executable's 
 * functions and data
 * 
 * @member programTree - the program tree root for modules and fragments 
 * related to this executable
 * 
 * @member provider - the ByteProvider used to read in the binary data of this 
 * executable
 * 
 * @member parentROM - the Ghidra Program representation of the UEFI ROM from 
 * which this executable was read
 */
public class EFIdraExecutableData {
	/**
	 * The name of the executable
	 */
	public String name;
	/**
	 * The base (starting) address of the executable
	 */
	public Address baseAddr;
	/**
	 * The namespace created for this executable's functions and data
	 */
	public Namespace namespace;
	/**
	 * The program tree root for modules and fragments related to this executable
	 */
	public ProgramModule programTree;
	/**
	 * The ByteProvider used to read in the binary data of this executable 
	 */
	public ByteProvider provider;
	/**
	 * The Ghidra Program representation of the UEFI ROM from which this
	 * executable was read
	 */
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
