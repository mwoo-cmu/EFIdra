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
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.GhidraLittleEndianDataConverter;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

public abstract class EFIdraParserScript extends GhidraScript {
	
	// maybe a getField helper function to get a field from an SDT
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
	
	protected void moveReaderToField(BinaryReader reader, StructureInternal sdt, 
			String fieldName) {
		reader.setPointerIndex(reader.getPointerIndex() + getOffsetToField(sdt, fieldName));
	}

	protected int readInt3(BinaryReader reader, long offset) throws IOException {
		byte[] intArray = reader.readByteArray(offset, 3);
		// little endian 3-byte integer
		return ((intArray[2] << 16) & 0xff0000) + ((intArray[1] << 8) & 0xff00) + 
				(intArray[0] & 0xff);
	}
	
	protected int readNextInt3(BinaryReader reader) throws IOException {
		byte[] intArray = reader.readNextByteArray(3);
		// little endian 3-byte integer
		return ((intArray[2] << 16) & 0xff0000) + ((intArray[1] << 8) & 0xff00) + 
				(intArray[0] & 0xff);
	}
	
	protected long readIntN(BinaryReader reader, long offset, int n) throws IOException {
		byte[] intArray = reader.readByteArray(offset, n);
		long mask = 0xff;
		long intval = intArray[0] & mask;
		for (int i = 1; i < n; i++) {
			intval += (intArray[i] & mask) << 8;
		}
		return intval;
	}
	
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
	
	protected ProgramModule createProgramModuleWithHeader(Program program, Address baseAddr,
			ProgramModule parent, DataType header, String name) 
					throws DuplicateNameException, NotFoundException, 
					AddressOutOfBoundsException, CodeUnitInsertionException {
		return createProgramModuleWithHeader(
				program.getListing(), baseAddr, parent, header, name);
	}
	
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
	
	protected ProgramFragment createProgramFragmentWithHeader(Program program, Address baseAddr,
			ProgramModule parent, DataType header, String name, long size) 
					throws DuplicateNameException, CodeUnitInsertionException, 
					NotFoundException, AddressOutOfBoundsException {
		return createProgramFragmentWithHeader(
				program.getListing(), baseAddr, parent, header, name, size);
	}
	
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
	
	protected short checksum16(BinaryReader reader, long length) throws IOException {
		long base = reader.getPointerIndex();
		long sum = 0;
		for (int i = 0; i < length; i += 2) {
			sum += ((long) reader.readShort(base + i)) & 0xffff;
		}
		return (short) (sum & 0xFFFF);
	}
	
	protected byte checksum8(BinaryReader reader, long length) throws IOException {
		long base = reader.getPointerIndex();
		long sum = 0;
		for (int i = 0; i < length; i++) {
			sum += ((long) reader.readByte(base + i)) & 0xff;
		}
		return (byte) (sum & 0xFF);
	}
	
	protected String guidToReadable(String guid) {
		EFIGUIDs guids = new EFIGUIDs();
		return guids.getReadableName(guid);
	}
	
	protected String guidBytesToReadable(byte[] guid) {
		EFIGUIDs guids = new EFIGUIDs();
		return guids.getReadableName(EFIGUIDs.bytesToGUIDString(guid));
	}
	
	protected String readGuid(BinaryReader reader, long offset) throws IOException {
		return guidBytesToReadable(reader.readByteArray(offset, EFIGUIDs.EFI_GUID_LEN));
	}
	
	protected String readNextGuid(BinaryReader reader) throws IOException {
		return guidBytesToReadable(reader.readNextByteArray(EFIGUIDs.EFI_GUID_LEN));
	}
	
	protected BinaryReader getBinaryReader(Program program) {
		Memory memory = program.getMemory();
		Address progBase = program.getImageBase();
		return new BinaryReader(new MemoryByteProvider(
				memory, progBase), 
				GhidraLittleEndianDataConverter.INSTANCE,
				memory.getMinAddress().subtract(progBase));
	}
	
	protected BinaryReader getBinaryReader(Program program, ProgramFragment fragment) {		
		Memory memory = program.getMemory();
		Address progBase = program.getImageBase();
		return new BinaryReader(new MemoryByteProvider(
				memory, progBase), 
				GhidraLittleEndianDataConverter.INSTANCE, 
				fragment.getMinAddress().subtract(progBase));
	}
	
	protected BinaryReader getBinaryReader(ProgramFragment fragment) {
		return getBinaryReader(currentProgram, fragment);
	}
	
	protected void loadExecutableAnalyzer(String name) throws GhidraScriptLoadException, IOException {
		EFIdraROMFormatLoader.addUserScript(name);
	}
	
	/**
	 * This method should be overridden by parsers to determine which fragments
	 * are executables, which should be exported by the exporter and 
	 * @param memory
	 * @param fragment
	 * @return
	 */
	public abstract boolean isExecutable(Program program, ProgramFragment fragment);
	
	/**
	 * This method should be overridden by parsers to specify the offset from 
	 * the beginning of the ProgramFragment to the beginning of the actual 
	 * executable file, to skip over any headers unrelated to the executable itself.
	 * @param program
	 * @param fragment
	 * @return
	 */
	public abstract long offsetToExecutable(Program program, ProgramFragment fragment);
	
	/**
	 * This method should specify whether this parser can be used to parse the 
	 * given program. 
	 * @param program all of the program data
	 * @return
	 */
	public abstract boolean canParse(Program program);

	public abstract void parseROM(Program program, TaskMonitor tMonitor);
	
	@Override
	protected void run() throws Exception {
		// by default, run the EFIdra Analyzer
		efidraAnalyzer analyzer = new efidraAnalyzer();
		analyzer.added(currentProgram, currentProgram.getAddressFactory().getAddressSet(), 
				monitor, new MessageLog());
	}

}
