package efidra;

import java.io.IOException;
import java.util.Arrays;

import ghidra.app.util.bin.BinaryReader;

public class EFIFirmwareFile {
	private static final int EFI_FF_SIZE_LEN = 3;
	private static final int EFI_FF_INTEGRITYCHECK_LEN = 2;
	public static final int EFI_FF_HEADER_LEN = 24;
	private static final int EFI_FF_HEADER_EXT_LEN = EFI_FF_HEADER_LEN + 8;
	
	private static final byte FFS_ATTRIB_LARGE_FILE = 0x01;
	private static final byte FFS_ATTRIB_DATA_ALIGNMENT_2 = 0x02;
	private static final byte FFS_ATTRIB_FIXED = 0x04;
	private static final byte FFS_ATTRIB_DATA_ALIGNMENT = 0x38;
	private static final byte FFS_ATTRIB_CHECKSUM = 0x40;
	
	/*
	 * /// Each file begins with the header that describe the
	 * /// contents and state of the files.
	 * typedef struct {
	 *   /// This GUID is the file name. It is used to uniquely identify the file.
	 *   EFI_GUID                   Name;
	 *   /// Used to verify the integrity of the file.
	 *   EFI_FFS_INTEGRITY_CHECK    IntegrityCheck;
	 *   /// Identifies the type of file.
	 *   EFI_FV_FILETYPE            Type;
	 *   /// Declares various file attribute bits.
	 *   EFI_FFS_FILE_ATTRIBUTES    Attributes;
	 *   /// The length of the file in bytes, including the FFS header.
	 *   UINT8                      Size[3];
	 *   /// Used to track the state of the file throughout the life of the file from creation to deletion.
	 *   EFI_FFS_FILE_STATE         State;
	 * } EFI_FFS_FILE_HEADER;
	 * 
	 * AND
	 * 
	 *   ///
  	 *   /// If FFS_ATTRIB_LARGE_FILE is set in Attributes, then ExtendedSize exists and Size must be set to zero.
  	 * 	 /// If FFS_ATTRIB_LARGE_FILE is not set then EFI_FFS_FILE_HEADER is used.
  	 * 	 ///
  	 *   UINT64                ExtendedSize;
	 * } EFI_FFS_FILE_HEADER2;
	 */
	
	private String name;
	private byte[] integrityCheck;
	private byte type;
	private byte attributes;
	private int size;
	private byte state;
	private long extendedSize;
	
	private boolean checksumValid;
	private long basePointer;
	private int headerSize;
	private byte[] fileData;
	
	private void parseHeader(BinaryReader reader) throws IOException {
		if ((attributes & FFS_ATTRIB_LARGE_FILE) != 0) {
			// size field is ignored
			extendedSize = reader.readNextLong();
			size = 0;
			headerSize = EFI_FF_HEADER_EXT_LEN;
		} else {
			headerSize = EFI_FF_HEADER_LEN;
		}
		
		if ((attributes & FFS_ATTRIB_CHECKSUM) != 0) {
			// integrityCheck[1] is the 8-bit checksum of the file itself
		} else {
			// if the attribute is not set, it should be 0xaa
			if (integrityCheck[1] != 0xaa) {
				checksumValid = false;
			}
		}
		
		reader.setPointerIndex(basePointer);
		// header sum should be 0, but need to adjust for state and file fields
		int headerSum = 0;
		for (int i = 0; i < headerSize; i++) {
			headerSum += reader.readNextByte();
		}
		headerSum -= state;
		headerSum -= integrityCheck[1];
		checksumValid &= (headerSum & 0xff) == 0;
		
		reader.setPointerIndex(basePointer + headerSize);
	}
	
	public EFIFirmwareFile(BinaryReader reader) throws IOException {
		basePointer = reader.getPointerIndex();
		
		// header
		name = EFIGUIDs.bytesToGUIDString(
				reader.readNextByteArray(EFIGUIDs.EFI_GUID_LEN));
		integrityCheck = reader.readNextByteArray(EFI_FF_INTEGRITYCHECK_LEN);
		type = reader.readNextByte();
		attributes = reader.readNextByte();
		byte[] sizeArray = reader.readNextByteArray(EFI_FF_SIZE_LEN);
		// little endian 3-byte integer
		size = ((sizeArray[2] << 16) & 0xff0000) + ((sizeArray[1] << 8) & 0xff00) + (sizeArray[0] & 0xff);
		state = reader.readNextByte();
		extendedSize = 0;
		
		parseHeader(reader);
		
		int dataLen = 0;
		if (extendedSize > 0) {
			dataLen = (int) (extendedSize - EFI_FF_HEADER_EXT_LEN);
		} else if (size > 0) {
			dataLen = size - EFI_FF_HEADER_LEN;
		}
		
		fileData = reader.readNextByteArray(dataLen);
	}
	
	public long getBasePointer() {
		return basePointer;
	}
	
	public String getNameGUID() {
		return name;
	}
	
	public long getSize() {
		return size == 0 ? extendedSize : (long) size;
	}
}
