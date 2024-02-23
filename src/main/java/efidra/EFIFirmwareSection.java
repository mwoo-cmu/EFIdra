package efidra;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

public class EFIFirmwareSection {
	private static final int EFI_SECTION_SIZE_LEN = 3;
	private static final int EFI_SECTION_EXT_SIZE_INDICATOR = 0xFFFFFF;
	public static final int EFI_SECTION_HEADER_SIZE = 4;
	public static final int EFI_SECTION_HEADER2_SIZE = 8;
	
	// Section Type values
	public static final byte EFI_SECTION_ALL = 0x00;
	public static final byte EFI_SECTION_COMPRESSION = 0x01;
	public static final byte EFI_SECTION_GUID_DEFINED = 0x02;
	public static final byte EFI_SECTION_PE32 = 0x10;
	public static final byte EFI_SECTION_PIC = 0x11;
	public static final byte EFI_SECTION_TE = 0x12;
	public static final byte EFI_SECTION_DXE_DEPEX = 0x13;
	public static final byte EFI_SECTION_VERSION = 0x14;
	public static final byte EFI_SECTION_USER_INTERFACE = 0x15;
	public static final byte EFI_SECTION_COMPATIBILITY16 = 0x16;
	public static final byte EFI_SECTION_FIRMWARE_VOLUME_IMAGE = 0x17;
	public static final byte EFI_SECTION_FREEFORM_SUBTYPE_GUID = 0x18;
	public static final byte EFI_SECTION_RAW = 0x19;
	public static final byte EFI_SECTION_PEI_DEPEX = 0x1B;
	public static final byte EFI_SECTION_MM_DEPEX = 0x1C;
	public static final byte EFI_SECTION_SMM_DEPEX = EFI_SECTION_MM_DEPEX;
	
	/*
	 * https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Pi/PiFirmwareFile.h#L240
	 * 
	 * /// Common section header.
	 * typedef struct { 
	 *   /// A 24-bit unsigned integer that contains the total size of the section in bytes,
  	 *   /// including the EFI_COMMON_SECTION_HEADER.
	 * 	 UINT8 Size[3];
	 * 	 /// Declares the section type. 
	 *   EFI_SECTION_TYPE Type; 
	 * } EFI_COMMON_SECTION_HEADER;
	 * 
	 * typedef struct { 
	 *   /// A 24-bit unsigned integer that contains the total size of the section in bytes,
     *   /// including the EFI_COMMON_SECTION_HEADER.
	 *   UINT8 Size[3]; 
	 *   /// Declares the section type.
	 *   EFI_SECTION_TYPE Type; 
	 *   /// If Size is 0xFFFFFF, then ExtendedSize contains the size of the section. If
     *   /// Size is not equal to 0xFFFFFF, then this field does not exist.
	 *   UINT32 ExtendedSize; 
	 * } EFI_COMMON_SECTION_HEADER2;
	 */
	private int size;
	private byte type;
//	private int extendedSize;
	private byte[] sectionData;
	private long basePointer;
	private int headerSize;
	
	private void parseHeader() {
		if (type == EFI_SECTION_COMPRESSION) {
//			//
//			// CompressionType of EFI_COMPRESSION_SECTION.
//			//
//			#define EFI_NOT_COMPRESSED        0x00
//			#define EFI_STANDARD_COMPRESSION  0x01
//			//
//			// An encapsulation section type in which the
//			// section data is compressed.
//			//
//			typedef struct {
//			  EFI_COMMON_SECTION_HEADER   CommonHeader;
//			  UINT32                      UncompressedLength;
//			  UINT8                       CompressionType;
//			} EFI_COMPRESSION_SECTION;
//
//			typedef struct {
//			  EFI_COMMON_SECTION_HEADER2  CommonHeader;
//			  UINT32                      UncompressedLength;
//			  UINT8                       CompressionType;
//			} EFI_COMPRESSION_SECTION2;
		} else if (type == EFI_SECTION_FREEFORM_SUBTYPE_GUID) {
//			//
//			// Leaf section which contains a single GUID.
//			//
//			typedef struct {
//			  EFI_COMMON_SECTION_HEADER   CommonHeader;
//			  EFI_GUID                    SubTypeGuid;
//			} EFI_FREEFORM_SUBTYPE_GUID_SECTION;
//
//			typedef struct {
//			  EFI_COMMON_SECTION_HEADER2  CommonHeader;
//			  EFI_GUID                    SubTypeGuid;
//			} EFI_FREEFORM_SUBTYPE_GUID_SECTION2;
		} else if (type == EFI_SECTION_GUID_DEFINED) {
//			//
//			// Attributes of EFI_GUID_DEFINED_SECTION
//			//
//			#define EFI_GUIDED_SECTION_PROCESSING_REQUIRED  0x01
//			#define EFI_GUIDED_SECTION_AUTH_STATUS_VALID    0x02
//			//
//			// Leaf section which is encapsulation defined by specific GUID
//			//
//			typedef struct {
//			  EFI_COMMON_SECTION_HEADER   CommonHeader;
//			  EFI_GUID                    SectionDefinitionGuid;
//			  UINT16                      DataOffset;
//			  UINT16                      Attributes;
//			} EFI_GUID_DEFINED_SECTION;
//
//			typedef struct {
//			  EFI_COMMON_SECTION_HEADER2  CommonHeader;
//			  EFI_GUID                    SectionDefinitionGuid;
//			  UINT16                      DataOffset;
//			  UINT16                      Attributes;
//			} EFI_GUID_DEFINED_SECTION2;
		} else if (type == EFI_SECTION_USER_INTERFACE) {
//			//
//			// Leaf section which contains a unicode string that
//			// is human readable file name.
//			//
//			typedef struct {
//			  EFI_COMMON_SECTION_HEADER   CommonHeader;
//
//			  //
//			  // Array of unicode string.
//			  //
//			  CHAR16                      FileNameString[1];
//			} EFI_USER_INTERFACE_SECTION;
//
//			typedef struct {
//			  EFI_COMMON_SECTION_HEADER2  CommonHeader;
//
//			  //
//			  // Array of unicode string.
//			  //
//			  CHAR16                      FileNameString[1];
//			} EFI_USER_INTERFACE_SECTION2;
		} else if (type == EFI_SECTION_VERSION) {
//			//
//			// Leaf section which contains a numeric build number and
//			// an optional unicode string that represent the file revision.
//			//
//			typedef struct {
//			  EFI_COMMON_SECTION_HEADER   CommonHeader;
//			  UINT16                      BuildNumber;
//			  CHAR16                      VersionString[1];
//			} EFI_VERSION_SECTION;
//
//			typedef struct {
//			  EFI_COMMON_SECTION_HEADER2  CommonHeader;
//			  UINT16                      BuildNumber;
//			  CHAR16                      VersionString[1];
//			} EFI_VERSION_SECTION2;
		}
		// All other types simply follow the standard EFI_COMMON_SECTION_HEADER
	}
	
	public EFIFirmwareSection(BinaryReader reader) throws IOException {
		basePointer = reader.getPointerIndex();
		byte[] sizeArray = reader.readNextByteArray(EFI_SECTION_SIZE_LEN);
		// little endian 3-byte integer
		size = ((sizeArray[2] << 16) & 0xff0000) + ((sizeArray[1] << 8) & 0xff00) + (sizeArray[0] & 0xff);
		type = reader.readNextByte();
		// 3 byte size + 1 byte type
		headerSize = EFI_SECTION_HEADER_SIZE;
		if (size == EFI_SECTION_EXT_SIZE_INDICATOR) {
			// we will write back into size for simplicity, since it is already an int
			size = reader.readNextInt();
			// 3 byte size + 1 byte type + 4 byte extendedSize
			headerSize = EFI_SECTION_HEADER2_SIZE;
		}
		
		sectionData = reader.readNextByteArray(size - headerSize);
	}
	
	public long getBasePointer() {
		return basePointer;
	}
	
	public byte getType() {
		return type;
	}
	
	public byte[] getSectionData() {
		return sectionData;
	}
	
	public int getHeaderSize() {
		return headerSize;
	}
	
	public int getSize() {
		return size;
	}
}
