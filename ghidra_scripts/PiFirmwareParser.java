import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import static java.util.Map.entry;

import efidra.EFIdraParserScript;
import efidra.EFIdraROMFormatLoader;
import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TerminatedUnicodeDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotFoundException;

public class PiFirmwareParser extends EFIdraParserScript {
	// "_FVH" stored little endian
	public static final int EFI_FVH_SIGNATURE = 0x4856465f;
	private static final int EFI_FV_OFFSET = 8;
	private static final int EFI_FF_HEADER_LEN = 24;
	private static final int EFI_FF_HEADER_EXT_LEN = EFI_FF_HEADER_LEN + 8;
	private static final byte FFS_ATTRIB_LARGE_FILE = 0x01;
	private static final byte FFS_ATTRIB_CHECKSUM = 0x40;
	private static final byte FFS_FIXED_CHECKSUM = (byte) 0xaa;
	
	private static final Map<String, String> TYPE_TO_HDR = Map.ofEntries(
			entry("EFI_SECTION_COMPRESSION", "EFI_COMPRESSION_SECTION"),
			entry("EFI_SECTION_FREEFORM_SUBTYPE_GUID", "EFI_FREEFORM_SUBTYPE_GUID_SECTION"),
			entry("EFI_SECTION_GUID_DEFINED", "EFI_GUID_DEFINED_SECTION"),
			entry("EFI_SECTION_USER_INTERFACE", "EFI_USER_INTERFACE_SECTION"),
			entry("EFI_SECTION_VERSION", "EFI_VERSION_SECTION"));
	
	private static byte[] FREE_SPACE_HEADER = new byte[EFI_FF_HEADER_LEN];
	private EnumDataType EFI_FV_FILETYPE;
	private EnumDataType EFI_SECTION_TYPE;
	private StructureDataType EFI_FIRMWARE_VOLUME_HEADER;
	private StructureDataType EFI_FIRMWARE_VOLUME_EXT_HEADER;
	private StructureDataType EFI_FFS_INTEGRITY_CHECK;
	private StructureDataType EFI_FFS_FILE_HEADER;
	private StructureDataType EFI_FFS_FILE_HEADER2;
	private StructureDataType EFI_COMMON_SECTION_HEADER;
	private StructureDataType EFI_COMMON_SECTION_HEADER2;
	
	private void loadStructures() {
		EFI_FV_FILETYPE = (EnumDataType)
				EFIdraROMFormatLoader.getType("EFI_FV_FILETYPE");
		EFI_SECTION_TYPE = (EnumDataType)
				EFIdraROMFormatLoader.getType("EFI_SECTION_TYPE");
		EFI_FIRMWARE_VOLUME_HEADER = (StructureDataType) 
				EFIdraROMFormatLoader.getType("EFI_FIRMWARE_VOLUME_HEADER");
		EFI_FIRMWARE_VOLUME_EXT_HEADER = (StructureDataType)
				EFIdraROMFormatLoader.getType("EFI_FIRMWARE_VOLUME_EXT_HEADER");
		EFI_FFS_INTEGRITY_CHECK = (StructureDataType)
				EFIdraROMFormatLoader.getType("EFI_FFS_INTEGRITY_CHECK");
		EFI_FFS_FILE_HEADER = (StructureDataType)
				EFIdraROMFormatLoader.getType("EFI_FFS_FILE_HEADER");
		EFI_FFS_FILE_HEADER2 = (StructureDataType)
				EFIdraROMFormatLoader.getType("EFI_FFS_FILE_HEADER2");
		EFI_COMMON_SECTION_HEADER = (StructureDataType)
				EFIdraROMFormatLoader.getType("EFI_COMMON_SECTION_HEADER");
		EFI_COMMON_SECTION_HEADER2 = (StructureDataType)
				EFIdraROMFormatLoader.getType("EFI_COMMON_SECTION_HEADER2");
		Arrays.fill(FREE_SPACE_HEADER, (byte)0xff);
	}
	
	private void parseSection(BinaryReader reader, Address progBase, Listing listing,
			ProgramModule parent) throws IOException, DuplicateNameException, 
			NotFoundException, AddressOutOfBoundsException, CodeUnitInsertionException {
		long baseIdx = reader.getPointerIndex();
		int size = readInt3(reader,
				baseIdx + getOffsetToField(EFI_COMMON_SECTION_HEADER, "Size"));
		byte sType = reader.readByte(
				baseIdx + getOffsetToField(EFI_COMMON_SECTION_HEADER, "Type"));
		String hdrExt = "";
		if (size == 0xffffff) {
			hdrExt = "2";
			size = reader.readInt(
					baseIdx + getOffsetToField(EFI_COMMON_SECTION_HEADER2, "ExtendedSize"));
		}
		String secType = EFI_SECTION_TYPE.getName(sType);
		String name = secType;
		String hdrType = TYPE_TO_HDR.get(secType);
		if (hdrType == null) {
			hdrType = "EFI_COMMON_SECTION_HEADER";
		}
		StructureDataType sdt = (StructureDataType) 
				EFIdraROMFormatLoader.getType(hdrType + hdrExt);
		
		if ("EFI_SECTION_USER_INTERFACE".equals(secType)) {
			long strOffs = getOffsetToField(sdt, "FileNameString");
			// get utf16 fileNameString until null terminator
			name = reader.readUnicodeString(baseIdx + strOffs);
			sdt = sdt.clone(null);
			// update the length of the string to match the actual string read
			sdt.replace(1, TerminatedUnicodeDataType.dataType, name.length());
		} else if ("EFI_SECTION_VERSION".equals(secType)) {
			long strOffs = getOffsetToField(sdt, "VersionString");
			// get utf16 fileNameString until null terminator
			String version = reader.readUnicodeString(baseIdx + strOffs);
			sdt = sdt.clone(null);
			// update the length of the string to match the actual string read
			sdt.replace(2, TerminatedUnicodeDataType.dataType, version.length());			
		} else if ("EFI_SECTION_COMPRESSION".equals(secType)) {
			// decompress
		}
		
		if ("EFI_SECTION_FIRMWARE_VOLUME_IMAGE".equals(secType)) {
			// create module and continue down
		} else {
			createProgramFragmentWithHeader(listing, progBase.add(baseIdx), parent, 
					sdt, name, size);
		}
		reader.setPointerIndex(baseIdx + size);
	}
	
	private void parseFile(BinaryReader reader, Address progBase, Listing listing,
			ProgramModule parent, long fvEnd) throws IOException, DuplicateNameException, 
				NotFoundException, AddressOutOfBoundsException, CodeUnitInsertionException {
		long baseIdx = reader.getPointerIndex();
		if (Arrays.equals(reader.readByteArray(baseIdx, EFI_FF_HEADER_LEN), 
				FREE_SPACE_HEADER)) {
			skipPadding(reader, 0xffffffff);
//			baseIdx = reader.getPointerIndex();
			// can't know where to start reading a file, label as non-uefi data
			ProgramFragment frag = parent.createFragment(
					"Non-UEFI Data (0x" + Long.toHexString(baseIdx) + ")");
			frag.move(progBase.add(baseIdx), progBase.add(fvEnd - 1));
			reader.setPointerIndex(fvEnd);
		} else {
			Address fileBase = progBase.add(baseIdx);
			
			// apply header
			String name = readGuid(reader, 
					baseIdx + getOffsetToField(EFI_FFS_FILE_HEADER, "Name"));
			byte attrs = reader.readByte(
					baseIdx + getOffsetToField(EFI_FFS_FILE_HEADER, "Attributes"));
			StructureDataType headerType;
			int size, hdrLen;
			if ((attrs & FFS_ATTRIB_LARGE_FILE) == 0) {
				size = readInt3(reader, 
						baseIdx + getOffsetToField(EFI_FFS_FILE_HEADER, "Size"));
				hdrLen = EFI_FF_HEADER_LEN;
				headerType = EFI_FFS_FILE_HEADER;
			} else {
				size = reader.readInt(
						baseIdx + getOffsetToField(EFI_FFS_FILE_HEADER2, "ExtendedSize"));
				hdrLen = EFI_FF_HEADER_EXT_LEN;
				headerType = EFI_FFS_FILE_HEADER2;
			}
			ProgramModule file = createProgramModuleWithHeader(listing, fileBase, parent, 
					 headerType, name);
			
			// check checksums
			long subtractedFields = ((long) reader.readByte(baseIdx 
					+ getOffsetToField(EFI_FFS_FILE_HEADER, "IntegrityCheck")
					+ getOffsetToField(EFI_FFS_INTEGRITY_CHECK, "File"))) & 0xff;
			subtractedFields += ((long) reader.readByte(
							baseIdx + getOffsetToField(EFI_FFS_FILE_HEADER, "State"))) & 0xff;
			String hdrChecksum = ((checksum8(reader, hdrLen) - subtractedFields) & 0xff) == 0 ? 
					"Header Checksum Valid" : "Header Checksum Invalid";
			String fileChecksum;
			long curIdx = baseIdx + hdrLen;
			reader.setPointerIndex(curIdx);
			if ((attrs & FFS_ATTRIB_CHECKSUM) == 0) {
				fileChecksum = reader.readByte(baseIdx
						+ getOffsetToField(EFI_FFS_FILE_HEADER, "IntegrityCheck")
						+ getOffsetToField(EFI_FFS_INTEGRITY_CHECK, "File")
						) == FFS_FIXED_CHECKSUM ?
								"File Checksum Valid" : "File Checksum Invalid";
			} else {
				fileChecksum = reader.readByte(baseIdx
						+ getOffsetToField(EFI_FFS_FILE_HEADER, "IntegrityCheck")
						+ getOffsetToField(EFI_FFS_INTEGRITY_CHECK, "File")
						) == (0x100 - checksum8(reader, size - hdrLen))?
								"File Checksum Valid" : "File Checksum Invalid";
			}
			listing.setComment(fileBase, CodeUnit.PRE_COMMENT, 
					hdrChecksum + ", " + fileChecksum);

			long fEnd = baseIdx + size;
			
			byte fType = reader.readByte(
					baseIdx + getOffsetToField(EFI_FFS_FILE_HEADER, "Type"));
			// RAW and PAD filetypes don't have sections
			if (fType != (byte) EFI_FV_FILETYPE.getValue("EFI_FV_FILETYPE_RAW") &&
					fType != (byte) EFI_FV_FILETYPE.getValue("EFI_FV_FILETYPE_FFS_PAD")) {
				// parse sections
				while (curIdx < fEnd) {
					reader.align(4);
					parseSection(reader, progBase, listing, file);
					curIdx = reader.getPointerIndex();
				}
			}
			reader.setPointerIndex(fEnd);
		}
	}
	
	private void parseVolume(BinaryReader reader, Address progBase, Listing listing, 
			ProgramModule parent) throws AddressOutOfBoundsException, 
				CodeUnitInsertionException, DuplicateNameException, NotFoundException, 
				IOException {
		long baseIdx = reader.getPointerIndex();
		// FV Header signature match, curIdx at the start of the header
		if (reader.readInt(baseIdx + getOffsetToField(
				EFI_FIRMWARE_VOLUME_HEADER, "Signature")) == EFI_FVH_SIGNATURE) {
			Address fvBase = progBase.add(baseIdx);
			short hdrLen = reader.readShort(
					baseIdx + getOffsetToField(EFI_FIRMWARE_VOLUME_HEADER, "HeaderLength"));
			
			// read the fields from the structure
			String name = readGuid(reader, 
					baseIdx + getOffsetToField(EFI_FIRMWARE_VOLUME_HEADER, "FileSystemGuid"));
			short extHeaderOffset = reader.readShort(baseIdx + getOffsetToField(
					EFI_FIRMWARE_VOLUME_HEADER, "ExtHeaderOffset"));
			long fileOffset = baseIdx + hdrLen;
			
			if (extHeaderOffset != 0) {
				// update name if available
				name = readGuid(reader, baseIdx + extHeaderOffset + getOffsetToField(
						EFI_FIRMWARE_VOLUME_EXT_HEADER, "FvName"));
			}
			
			// create the volume
			ProgramModule volume = createProgramModuleWithHeader(listing, fvBase, parent, 
					EFI_FIRMWARE_VOLUME_HEADER, name);
			
			// check if there's an extended header
			if (extHeaderOffset != 0) {
				
				// create extended header structure
				Address extHdrBase = fvBase.add(extHeaderOffset);
				listing.createData(extHdrBase, EFI_FIRMWARE_VOLUME_EXT_HEADER);
				
				// add the extended header to the header fragment for easier readability
				int extHdrSize = reader.readInt(baseIdx + extHeaderOffset
						+ getOffsetToField(EFI_FIRMWARE_VOLUME_EXT_HEADER, "ExtHeaderSize"));
				((ProgramFragment) volume.getChildren()[0]).move(extHdrBase, extHdrBase.add(extHdrSize - 1));
				
				fileOffset = baseIdx + extHeaderOffset + extHdrSize;
			}
			
			// check 16-bit fv header checksum
			listing.setComment(fvBase, CodeUnit.PRE_COMMENT, 
					(checksum16(reader, hdrLen) == 0) ? "Checksum Valid" : "Checksum Invalid");
			
			// parse files in volume
			long fvEnd = baseIdx + reader.readLong(
					baseIdx + getOffsetToField(EFI_FIRMWARE_VOLUME_HEADER, "FvLength"));
			long curIdx = fileOffset;
			// set reader to start of files
			reader.setPointerIndex(curIdx);
			while (curIdx < fvEnd) {
				reader.align(EFI_FV_OFFSET);
				parseFile(reader, progBase, listing, volume, fvEnd);
				curIdx = reader.getPointerIndex();
			}
			
			// set pointer to the end of the volume (start of the next volume)
			reader.setPointerIndex(fvEnd);
		} else {
			// skip 8 bytes, try again
			reader.readNextLong();					
		}
	}
	
	public void parseROM(Program program) {
		loadStructures();
		BinaryReader reader = getBinaryReader(program);
		Listing listing = program.getListing();
		Address progBase = program.getImageBase();
		ProgramModule rootModule = listing.getDefaultRootModule();
		
		try {
			// find the start of the ROM excluding all the padding at the beginning
			skipPadding(reader, 0);
			reader.align(EFI_FV_OFFSET);
			// need to offset by the size of the zero vector
			long curIdx = reader.getPointerIndex() - 16;
			long fileLen = reader.length() - 1;
			reader.setPointerIndex(curIdx);
			while (curIdx < fileLen) {
				parseVolume(reader, progBase, listing, rootModule);
				curIdx = reader.getPointerIndex();
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (DuplicateNameException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (AddressOutOfBoundsException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CodeUnitInsertionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public boolean isExecutable(Program program, ProgramFragment fragment) {
		BinaryReader reader = getBinaryReader(program, fragment);
		try {
			moveReaderToField(reader, EFI_COMMON_SECTION_HEADER, "Type");
			byte sType = reader.readNextByte();
			return (sType == EFI_SECTION_TYPE.getValue("EFI_SECTION_PE32") || 
					sType == EFI_SECTION_TYPE.getValue("EFI_SECTION_TE"));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}
	
	@Override
	public long offsetToExecutable(Program program, ProgramFragment fragment) {
		return program.getListing().getDataAt(fragment.getMinAddress()).getDataType().getLength();
	}
}
