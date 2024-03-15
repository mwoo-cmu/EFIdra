package efidra;
import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotFoundException;

public class EFIdraParserScript extends GhidraScript {
	
	// maybe createProgramFragment and createProgramModule?
	// can we pull data from StructureDataTypes?
	
	// can parse within a header with sdt.getComponents() .. .getLength()
	// maybe a getField helper function to get a field from an SDT, so that a 
	// user can use the length field in a header
		// maybe automatically apply length if the field is there?
	protected long getOffsetToField(StructureDataType sdt, String fieldName) {
		int offset = 0;
		for (DataTypeComponent comp : sdt.getComponents()) {
			if (fieldName.equals(comp.getFieldName())) {
				break;
			}
			offset += comp.getLength();
		}
		return offset;
	}
	
	protected void moveReaderToField(BinaryReader reader, StructureDataType sdt, 
			String fieldName) {
		reader.setPointerIndex(reader.getPointerIndex() + getOffsetToField(sdt, fieldName));
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
		int sum = 0;
		for (int i = 0; i < length; i += 2) {
			sum += reader.readShort(base + i);
		}
		return (short) (sum & 0xFFFF);
	}
	
	protected byte checksum8(BinaryReader reader, long length) throws IOException {
		long base = reader.getPointerIndex();
		int sum = 0;
		for (int i = 0; i < length; i ++) {
			sum += reader.readByte(base + i);
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
	
	protected BinaryReader getBinaryReader(Program program) {
		return new BinaryReader(new MemoryByteProvider(
				program.getMemory(), program.getImageBase()), true);
	}
	
	/**
	 * This method should be overridden by parsers to determine which fragments
	 * are executables, which should be exported by the exporter and 
	 * @param fragment
	 * @return
	 */
	public boolean isExecutable(ProgramFragment fragment) {
		return false;
	}

	public void parseROM(Program program) {
	}
	
	@Override
	protected void run() throws Exception {
		// TODO Auto-generated method stub
		Msg.info(null, getScriptName());
	}

}
