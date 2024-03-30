package efidra;
import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptLoadException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.StructureInternal;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.GhidraLittleEndianDataConverter;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

public abstract class EFIdraParserScript extends GhidraScript {
	/**
	 * This method should be overridden by parsers to determine which fragments
	 * are executables, which should be exported by the exporter and 
	 * @param program The program in Ghidra representing the entire ROM
	 * @param fragment The chunk of the ROM bytes that may or may not represent
	 * 	an executable
	 * @return whether or not the given ProgramFragment is an executable
	 */
	public abstract boolean isExecutable(Program program, ProgramFragment fragment);
	
	/**
	 * This method should be overridden by parsers to specify the offset from 
	 * the beginning of the ProgramFragment to the beginning of the actual 
	 * executable file, to skip over any headers unrelated to the executable itself.
	 * @param program The program in Ghidra representing the entire ROM
	 * @param fragment The chunk of ROM bytes representing an executable
	 * @return The offset from the start of the fragment to the start of the 
	 * 	actual executable binary data (e.g. the offset to the magic bytes for 
	 * portable executables and terse executables)
	 */
	public abstract long offsetToExecutable(Program program, ProgramFragment fragment);
	
	/**
	 * This method should specify whether this parser can be used to parse the 
	 * given program. 
	 * @param program all of the program data
	 * @return
	 */
	public abstract boolean canParse(Program program);

	/**
	 * This method should be implemented to actually parse the ROM provided in 
	 * program. 
	 * @param program The Ghidra program representing the UEFI ROM
	 * @param tMonitor The task monitor for this parsing job
	 */
	public abstract void parseROM(Program program, TaskMonitor tMonitor);
	
	/**
	 * Gets the offset, in bytes, to the given fieldName of the given Structure
	 * type 
	 * @param sdt The Structure definition to pull the offset to the field from
	 * @param fieldName The name of the field in the structure to get the 
	 * offset to
	 * @return The offset, in bytes, to the given fieldName of the structure 
	 * from the start of the structure
	 */
	protected long getOffsetToField(StructureInternal sdt, String fieldName) {
		int offset = 0;
		for (DataTypeComponent comp : sdt.getComponents()) {
			if (fieldName.equals(comp.getFieldName())) {
				break;
			}
			offset += comp.getLength();
		}
		return offset;
	}
	
	/**
	 * Moves the current index of the given reader to the address of the given 
	 * fieldName in the given sdt Structure type, assuming that the reader's
	 * current index is at the start of the sdt Structure type
	 * @param reader The reader to move the current index of
	 * @param sdt The Structure definition to pull the offset to the field from
	 * @param fieldName The name of the field in the structure to move the 
	 * reader to
	 */
	protected void moveReaderToField(BinaryReader reader, StructureInternal sdt, 
			String fieldName) {
		reader.setPointerIndex(reader.getPointerIndex() + getOffsetToField(sdt, fieldName));
	}

	/**
	 * Reads in a 3-byte integer starting at the given offset index from the 
	 * given reader
	 * @param reader The reader from which to read in the 3-byte integer
	 * @param offset The index offset at which the 3-byte integer starts
	 * @return The integer read from the reader
	 * @throws IOException if an error occurs while reading in bytes
	 */
	protected int readInt3(BinaryReader reader, long offset) throws IOException {
		byte[] intArray = reader.readByteArray(offset, 3);
		// little endian 3-byte integer
		return ((intArray[2] << 16) & 0xff0000) + ((intArray[1] << 8) & 0xff00) + 
				(intArray[0] & 0xff);
	}
	
	/**
	 * Reads in the 3-byte integer at the given reader's current index, and
	 * then advances the reader's index by 3 bytes
	 * @param reader The reader from which to read the 3-byte integer
	 * @return The integer value read from the integer
	 * @throws IOException if an error occurs while reading in bytes
	 */
	protected int readNextInt3(BinaryReader reader) throws IOException {
		byte[] intArray = reader.readNextByteArray(3);
		// little endian 3-byte integer
		return ((intArray[2] << 16) & 0xff0000) + ((intArray[1] << 8) & 0xff00) + 
				(intArray[0] & 0xff);
	}
	
	/**
	 * Reads in an n-byte integer starting at the given offset index from the 
	 * given reader
	 * @param reader The reader from which to read in the n-byte integer
	 * @param offset The index offset at which the n-byte integer starts
	 * @param n The number of bytes in the integer to read
	 * @return The integer read from the reader
	 * @throws IOException if an error occurs while reading in bytes
	 */
	protected long readIntN(BinaryReader reader, long offset, int n) throws IOException {
		byte[] intArray = reader.readByteArray(offset, n);
		long mask = 0xff;
		long intval = intArray[0] & mask;
		for (int i = 1; i < n; i++) {
			intval += (intArray[i] & mask) << 8;
		}
		return intval;
	}

	/**
	 * Reads in the n-byte integer at the given reader's current index, and
	 * then advances the reader's index by n bytes
	 * @param reader The reader from which to read in the n-byte integer
	 * @param n The number of bytes in the integer to read
	 * @return The integer read from the reader
	 * @throws IOException if an error occurs while reading in bytes
	 */
	protected long readNextIntN(BinaryReader reader, int n) throws IOException {
		byte[] intArray = reader.readNextByteArray(n);
		long mask = 0xff;
		long intval = intArray[0] & mask;
		for (int i = 1; i < n; i++) {
			intval += (intArray[i] & mask) << 8;
		}
		return intval;
	}
	
	/**
	 * Moves the reader current index to the first byte value which is not 
	 * equal to the given paddingValue
	 * @param reader The reader to move to the end of the padding
	 * @param paddingValue The 1-byte value of the padding
	 * @throws IOException if an error occurs while reading in bytes
	 */
	protected void skipPadding(BinaryReader reader, byte paddingValue) throws IOException {
		long readerLen = reader.length();
		long curIdx = reader.getPointerIndex();
		while (curIdx < readerLen) {
			byte next = reader.readNextByte();
			if (next != paddingValue) {
				reader.setPointerIndex(curIdx);
				return;
			}
			curIdx = reader.getPointerIndex();
		}
	}

	/**
	 * Moves the reader current index to the first 2-byte value which is not
	 * equal to the given paddingValue
	 * @param reader The reader to move to the end of the padding
	 * @param paddingValue The 2-byte value of the padding
	 * @throws IOException if an error occurs while reading in bytes
	 */
	protected void skipPadding(BinaryReader reader, short paddingValue) throws IOException {
		long readerLen = reader.length();
		long curIdx = reader.getPointerIndex();
		while (curIdx < readerLen) {
			short next = reader.readNextShort();
			if (next != paddingValue) {
				reader.setPointerIndex(curIdx);
				return;
			}
			curIdx = reader.getPointerIndex();
		}
	}
	
	/**
	 * Moves the reader current index to the first integer value which is not 
	 * equal to the given paddingValue
	 * @param reader The reader to move to the end of the padding
	 * @param paddingValue The integer (4-byte) value of the padding
	 * @throws IOException if an error occurs while reading in bytes
	 */
	protected void skipPadding(BinaryReader reader, int paddingValue) throws IOException {
		long readerLen = reader.length();
		long curIdx = reader.getPointerIndex();
		while (curIdx < readerLen) {
			int next = reader.readNextInt();
			if (next != paddingValue) {
				reader.setPointerIndex(curIdx);
				return;
			}
			curIdx = reader.getPointerIndex();
		}
	}
	
	/**
	 * Creates a ProgramModule (folder in the program tree) under a given 
	 * parent module, with a given name. This will also create a 
	 * ProgramFragment containing the given header DataType, which should 
	 * start at the current index of the given reader.
	 * @param program The Program representation of the UEFI ROM
	 * @param reader The BinaryReader whose current index is the start of the
	 * new ProgramFragment 
	 * @param parent The parent module (folder) under which to create this
	 * module
	 * @param header The header data type, which will get applied at the given
	 * baseAddr and placed into the new module
	 * @param name The name that should be assigned to the new module
	 * @return The created ProgramModule, with a ProgramFragment containing the
	 * given header DataType at the given baseAddr
	 * @throws DuplicateNameException If the given name is already in use in 
	 * the program tree
	 * @throws NotFoundException If any of the addresses in the range from
	 * baseAddr to baseAddr + header.getLength() - 1 is outside of the 
	 * available address range
	 * @throws AddressOutOfBoundsException If adding header.getLength() - 1 to
	 * the baseAddr would result in an out-of-bounds address 
	 * @throws CodeUnitInsertionException If there was an error creating the
	 * header DataType at the baseAddr
	 */
	protected ProgramModule createProgramModuleWithHeader(Program program, BinaryReader reader, 
			ProgramModule parent, DataType header, String name) 
					throws DuplicateNameException, NotFoundException, 
					AddressOutOfBoundsException, CodeUnitInsertionException {
		long baseAddr = reader.getPointerIndex();
		Address progBase = program.getImageBase();
		Address hdrBase = progBase.add(baseAddr);
		return createProgramModuleWithHeader(
				program.getListing(), hdrBase, parent, header, name);
	}
	
	/**
	 * Creates a ProgramModule (folder in the program tree) under a given 
	 * parent module, with a given name. This will also create a 
	 * ProgramFragment containing the given header DataType, which should 
	 * start at the given baseAddr.
	 * @param program The Program representation of the UEFI ROM
	 * @param baseAddr The address at which the given header data type starts
	 * @param parent The parent module (folder) under which to create this
	 * module
	 * @param header The header data type, which will get applied at the given
	 * baseAddr and placed into the new module
	 * @param name The name that should be assigned to the new module
	 * @return The created ProgramModule, with a ProgramFragment containing the
	 * given header DataType at the given baseAddr
	 * @throws DuplicateNameException If the given name is already in use in 
	 * the program tree
	 * @throws NotFoundException If any of the addresses in the range from
	 * baseAddr to baseAddr + header.getLength() - 1 is outside of the 
	 * available address range
	 * @throws AddressOutOfBoundsException If adding header.getLength() - 1 to
	 * the baseAddr would result in an out-of-bounds address 
	 * @throws CodeUnitInsertionException If there was an error creating the
	 * header DataType at the baseAddr
	 */
	protected ProgramModule createProgramModuleWithHeader(Program program, Address baseAddr,
			ProgramModule parent, DataType header, String name) 
					throws DuplicateNameException, NotFoundException, 
					AddressOutOfBoundsException, CodeUnitInsertionException {
		return createProgramModuleWithHeader(
				program.getListing(), baseAddr, parent, header, name);
	}
	
	/**
	 * Creates a ProgramModule (folder in the program tree) under a given 
	 * parent module, with a given name. This will also create a 
	 * ProgramFragment containing the given header DataType, which should 
	 * start at the given baseAddr.
	 * @param listing The program listing, used for creating the header DataType
	 * @param baseAddr The address at which the given header data type starts
	 * @param parent The parent module (folder) under which to create this
	 * module
	 * @param header The header data type, which will get applied at the given
	 * baseAddr and placed into the new module
	 * @param name The name that should be assigned to the new module
	 * @return The created ProgramModule, with a ProgramFragment containing the
	 * given header DataType at the given baseAddr
	 * @throws DuplicateNameException If the given name is already in use in 
	 * the program tree
	 * @throws NotFoundException If any of the addresses in the range from
	 * baseAddr to baseAddr + header.getLength() - 1 is outside of the 
	 * available address range
	 * @throws AddressOutOfBoundsException If adding header.getLength() - 1 to
	 * the baseAddr would result in an out-of-bounds address 
	 * @throws CodeUnitInsertionException If there was an error creating the
	 * header DataType at the baseAddr
	 */
	protected ProgramModule createProgramModuleWithHeader(Listing listing, Address baseAddr, 
			ProgramModule parent, DataType header, String name) 
					throws DuplicateNameException, NotFoundException, 
					AddressOutOfBoundsException, CodeUnitInsertionException {
		String baseAddrHex = " (0x" + Long.toHexString(baseAddr.getOffset()) + ")";
		ProgramModule module = parent.createModule(name + baseAddrHex);
		ProgramFragment frag = module.createFragment(
				"Header" + baseAddrHex + " " + header.getDisplayName());
		frag.move(baseAddr, baseAddr.add(header.getLength() - 1));
		listing.createData(baseAddr, header);
		return module;
	}
	
	/**
	 * Creates a ProgramFragment under the given parent module, starting at the
	 * current index of the given BinaryReader, with the given name and size in 
	 * bytes. The given header DataType is automatically applied at the start 
	 * of the new ProgramFragment. 
	 * @param program The program representation of the UEFI ROM
	 * @param reader The BinaryReader whose current index is the start of the
	 * new ProgramFragment 
	 * @param parent The parent module (folder) under which to create this
	 * fragment
	 * @param header The data type of the header, which should be applied at 
	 * the start of this fragment
	 * @param name The name that should be assigned to this new fragment
	 * @param size The size, in bytes, of the fragment to create
	 * @return The created ProgramFragment, with the initialized data at the 
	 * start
	 * @throws DuplicateNameException If the given name is already in use in 
	 * the program tree
	 * @throws NotFoundException If the any of the addresses in the range from
	 * the baseAddr to baseAddr + size is outside of the available addresses
	 * @throws AddressOutOfBoundsException If the addition of the size bytes 
	 * to the given baseAddr would produce an address out of bounds
	 * @throws CodeUnitInsertionException If there was an error creating the
	 * data type for the header at the start of the fragment.
	 */
	protected ProgramFragment createProgramFragmentWithHeader(Program program, 
			BinaryReader reader, ProgramModule parent, DataType header, String name,
			long size) throws DuplicateNameException, NotFoundException, 
			AddressOutOfBoundsException, CodeUnitInsertionException {
		long baseAddr = reader.getPointerIndex();
		Address progBase = program.getImageBase();
		Address hdrBase = progBase.add(baseAddr);
		return createProgramFragmentWithHeader(
				program.getListing(), hdrBase, parent, header, name, size);
	}
	
	/**
	 * Creates a ProgramFragment under the given parent module, starting at the
	 * given baseAddr, with the given name and size in bytes. The given header 
	 * DataType is automatically applied at the start of the new 
	 * ProgramFragment. 
	 * @param program The program representation of the UEFI ROM
	 * @param baseAddr The base address of the header, from which the fragment 
	 * will be created
	 * @param parent The parent module (folder) under which to create this
	 * fragment
	 * @param header The data type of the header, which should be applied at 
	 * the start of this fragment
	 * @param name The name that should be assigned to this new fragment
	 * @param size The size, in bytes, of the fragment to create
	 * @return The created ProgramFragment, with the initialized data at the 
	 * start
	 * @throws DuplicateNameException If the given name is already in use in 
	 * the program tree
	 * @throws NotFoundException If the any of the addresses in the range from
	 * the baseAddr to baseAddr + size is outside of the available addresses
	 * @throws AddressOutOfBoundsException If the addition of the size bytes 
	 * to the given baseAddr would produce an address out of bounds
	 * @throws CodeUnitInsertionException If there was an error creating the
	 * data type for the header at the start of the fragment.
	 */
	protected ProgramFragment createProgramFragmentWithHeader(Program program, Address baseAddr,
			ProgramModule parent, DataType header, String name, long size) 
					throws DuplicateNameException, CodeUnitInsertionException, 
					NotFoundException, AddressOutOfBoundsException {
		return createProgramFragmentWithHeader(
				program.getListing(), baseAddr, parent, header, name, size);
	}
	
	/**
	 * Creates a ProgramFragment under the given parent module, starting at the
	 * given baseAddr, with the given name and size in bytes. The given header 
	 * DataType is automatically applied at the start of the new 
	 * ProgramFragment. 
	 * @param listing The listing from the program, used to create the data item
	 * @param baseAddr The base address of the header, from which the fragment 
	 * will be created
	 * @param parent The parent module (folder) under which to create this
	 * fragment
	 * @param header The data type of the header, which should be applied at 
	 * the start of this fragment
	 * @param name The name that should be assigned to this new fragment
	 * @param size The size, in bytes, of the fragment to create
	 * @return The created ProgramFragment, with the initialized data at the 
	 * start
	 * @throws DuplicateNameException If the given name is already in use in 
	 * the program tree
	 * @throws NotFoundException If the any of the addresses in the range from
	 * the baseAddr to baseAddr + size is outside of the available addresses
	 * @throws AddressOutOfBoundsException If the addition of the size bytes 
	 * to the given baseAddr would produce an address out of bounds
	 * @throws CodeUnitInsertionException If there was an error creating the
	 * data type for the header at the start of the fragment.
	 */
	protected ProgramFragment createProgramFragmentWithHeader(Listing listing, Address baseAddr,
			ProgramModule parent, DataType header, String name, long size) 
					throws DuplicateNameException, NotFoundException, 
					AddressOutOfBoundsException, CodeUnitInsertionException {
		String baseAddrHex = " (0x" + Long.toHexString(baseAddr.getOffset()) + ")";
		ProgramFragment frag = parent.createFragment(name + baseAddrHex);
		frag.move(baseAddr, baseAddr.add(size - 1));
		listing.createData(baseAddr, header);
		return frag;
	}
	
	/**
	 * Calculates the 16-bit checksum over the given length of bytes from the
	 * reader's current index. When complete, the reader's pointer will be at 
	 * the end of the bytes used in the checksum calculation
	 * @param reader The reader to read bytes from for the checksum calculation
	 * @param length The length of bytes to read from the reader
	 * @return The truncated 16-bit sum over the bytes read from the reader
	 * @throws IOException if there was an error reading in bytes
	 */
	protected short checksum16(BinaryReader reader, long length) throws IOException {
		long base = reader.getPointerIndex();
		long sum = 0;
		for (int i = 0; i < length; i += 2) {
			sum += ((long) reader.readShort(base + i)) & 0xffff;
		}
		return (short) (sum & 0xFFFF);
	}
	
	/**
	 * Calculate the 8-bit checksum over the given length of bytes from the 
	 * reader's current index. When complete, the reader's pointer will be at
	 * the end of the bytes used in the checksum calculation
	 * @param reader The reader to read bytes from for the checksum calculation
	 * @param length The length of bytes to read from the reader
	 * @return The truncated 8-bit sum over the bytes read from the reader
	 * @throws IOException if there was an error reading in bytes
	 */
	protected byte checksum8(BinaryReader reader, long length) throws IOException {
		long base = reader.getPointerIndex();
		long sum = 0;
		for (int i = 0; i < length; i++) {
			sum += ((long) reader.readByte(base + i)) & 0xff;
		}
		return (byte) (sum & 0xFF);
	}
	
	/**
	 * Convers the given GUID String representation into its human-readable
	 * String name, if available
	 * @param guid The String representation of the GUID
	 * @return The human-readable String name if available, and the given 
	 * String representation of the GUID otherwise.
	 */
	protected String guidToReadable(String guid) {
		EFIGUIDs guids = new EFIGUIDs();
		return guids.getReadableName(guid);
	}
	
	/**
	 * Converts the given GUID byte array (likely read from a BinaryReader) 
	 * to its human-readable string name, if available.
	 * @param guid The byte array representing the GUID data
	 * @return The human-readable String name if available, and the String 
	 * representation of the GUID otherwise. 
	 */
	protected String guidBytesToReadable(byte[] guid) {
		EFIGUIDs guids = new EFIGUIDs();
		return guids.getReadableName(EFIGUIDs.bytesToGUIDString(guid));
	}
	
	/**
	 * Reads the 16-byte GUID at the given offset index
	 * @param reader The reader to read the GUID from
	 * @param offset The index offset at which to start reading the GUID
	 * @return A String representation of the GUID read
	 * @throws IOException if there was an error reading the bytes
	 */
	protected String readGuid(BinaryReader reader, long offset) throws IOException {
		return guidBytesToReadable(reader.readByteArray(offset, EFIGUIDs.EFI_GUID_LEN));
	}
	
	/**
	 * Reads the 16-byte GUID at the current index and then increments the 
	 * current index by 16 bytes. 
	 * @param reader The reader to read the GUID from
	 * @return A String representation of the GUID read
	 * @throws IOException if there was an error reading the bytes
	 */
	protected String readNextGuid(BinaryReader reader) throws IOException {
		return guidBytesToReadable(reader.readNextByteArray(EFIGUIDs.EFI_GUID_LEN));
	}
	
	/**
	 * Creates a BinaryReader over the entire given program
	 * @param program The program representing the UEFI ROM
	 * @return the BinaryReader object for reading bytes from the program
	 */
	protected BinaryReader getBinaryReader(Program program) {
		Memory memory = program.getMemory();
		Address progBase = program.getImageBase();
		return new BinaryReader(new MemoryByteProvider(
				memory, progBase), 
				GhidraLittleEndianDataConverter.INSTANCE,
				memory.getMinAddress().subtract(progBase));
	}
	
	/**
	 * Creates a BinaryReader over the given ProgramFragment
	 * @param program The program representing the UEFI ROM
	 * @param fragment The fragment of the program data to read from
	 * @return the BinaryReader object for reading the fragment
	 */
	protected BinaryReader getBinaryReader(Program program, ProgramFragment fragment) {		
		Memory memory = program.getMemory();
		Address progBase = program.getImageBase();
		return new BinaryReader(new MemoryByteProvider(
				memory, progBase), 
				GhidraLittleEndianDataConverter.INSTANCE, 
				fragment.getMinAddress().subtract(progBase));
	}
	
	/**
	 * Creates a BinaryReader over the given ProgramFragment. Requires that the
	 * currentProgram attribute of this script is set.
	 * @param fragment The fragment to read data from
	 * @return the BinaryReader object for reading the fragment
	 */
	protected BinaryReader getBinaryReader(ProgramFragment fragment) {
		return getBinaryReader(currentProgram, fragment);
	}
	
	/**
	 * Loads in a Java GhidraScript file specified by the given name to be used
	 * to attempt to analyze any modules designated as executables by the parser  
	 * @param name The name of the GhidraScript to load in
	 * @throws GhidraScriptLoadException if there is an error loading in the script
	 * @throws IOException if there is an error reading the file
	 */
	protected void loadExecutableAnalyzer(String name) throws GhidraScriptLoadException, IOException {
		EFIdraROMFormatLoader.addUserScript(name);
	}
	
	/**
	 * Labels the GUID at the given offset from the given progBase with a
	 * comment of its readable name, if available. This should be called during 
	 * the parsing process, and should not be used if labelAllGuids is used.
	 * @param reader The reader from which to read GUID data
	 * @param progBase The base address of the program
	 * @param listing The listing in which to create comments
	 * @param offset The offset from the base address at which the GUID lies
	 * @throws IOException if an error occurred reading the GUID bytes
	 */
	protected void labelGuid(BinaryReader reader, Address progBase, Listing listing, 
			long offset) throws IOException {
		String guidName = guidToReadable(readGuid(reader, offset));
		listing.setComment(progBase.add(offset), CodeUnit.EOL_COMMENT, guidName);
	}
	
	/**
	 * Recursively labels any components of the given data of the type EFI_GUID
	 * with a comment of its readable name, if available. Used internally in 
	 * labelAllGuids.
	 * @param listing The listing in which to create comments
	 * @param data The data to find GUIDs in
	 */
	private void labelGuidsRecursive(Listing listing, Data data) {
		if ("EFI_GUID".equals(data.getDataType().getName())) {
			try {
				byte[] guidBytes = data.getBytes();
				String guidName = guidBytesToReadable(guidBytes);
//				symbolTable.createLabel(data.getAddress(), guidName, , SourceType.ANALYSIS);
				listing.setComment(data.getAddress(), CodeUnit.EOL_COMMENT, guidName);
			} catch (MemoryAccessException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} else if (data.getNumComponents() > 1) {
			for (int i = 0; i < data.getNumComponents(); i++) {
				labelGuidsRecursive(listing, data.getComponent(i));
			}
		}
	}
	
	/**
	 * Iterates over the program and labels any data with the type EFI_GUID 
	 * with a comment of its readable name, if available. This should be called
	 * after parsing is complete. 
	 * @param program The progam to label GUIDs in
	 */
	protected void labelAllGuids(Program program) {
		Listing listing = program.getListing();
		DataIterator iter = listing.getDefinedData(true);
		while (iter.hasNext()) {
			Data data = iter.next();
			labelGuidsRecursive(listing, data);
		}
	}
	
	@Override
	protected void run() throws Exception {
		// by default, run the EFIdra Analyzer
		efidraAnalyzer analyzer = new efidraAnalyzer();
		analyzer.added(currentProgram, currentProgram.getAddressFactory().getAddressSet(), 
				monitor, new MessageLog());
	}

}
