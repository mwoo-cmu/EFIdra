package efidra;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.mem.Memory;
import ghidra.util.GhidraLittleEndianDataConverter;

public class EFIFirmwareVolume {
	private class EFIFVBlockMapEntry {
		/*
		 * typedef struct {
		 *   /// The number of sequential blocks which are of the same size.
		 *   UINT32    NumBlocks;
		 *   /// The size of the blocks.
		 *   UINT32    Length;
		 * } EFI_FV_BLOCK_MAP_ENTRY;
		 */
		public int numBlocks;
		public int length;
		
		public EFIFVBlockMapEntry(int numBlocks, int length) {
			this.numBlocks = numBlocks;
			this.length = length;
		}
	}
	
	// "_FVH" stored little endian
	public static final int EFI_FVH_SIGNATURE = 0x4856465f;
	
	public static final int ZERO_VECTOR_LEN = 16;
	// from zeroVector + fileSystemGuid + fvLength
	public static final int EFI_SIG_OFFSET = ZERO_VECTOR_LEN + EFIGUIDs.EFI_GUID_LEN + 8;
	public static final int EFI_FV_CHECKSUM_OFFSET = EFI_SIG_OFFSET + 4 + 4 + 2;
	private static final int EFI_FV_OFFSET = 8;
	
	private static byte[] FREE_SPACE_HEADER = new byte[EFIFirmwareFile.EFI_FF_HEADER_LEN];
	
	private static final int EFI_FVB2_ALIGNMENT = 0x001F0000; // refers to 2GB alignment
	
	/* from https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Pi/PiFirmwareVolume.h
	 * /// Describes the features and layout of the firmware volume.
	 * typedef struct {
	 * 	/// The first 16 bytes are reserved to allow for the reset vector of
	 * 	/// processors whose reset vector is at address 0.
	 * 	UINT8                     ZeroVector[16];
	 *  /// Declares the file system with which the firmware volume is formatted.
	 *  EFI_GUID                  FileSystemGuid;
	 *  /// Length in bytes of the complete firmware volume, including the header.
	 *  UINT64                    FvLength;
	 *  /// Set to EFI_FVH_SIGNATURE
	 *  UINT32                    Signature;
	 *  /// Declares capabilities and power-on defaults for the firmware volume.
	 *  EFI_FVB_ATTRIBUTES_2      Attributes;
	 *  /// Length in bytes of the complete firmware volume header.
	 *  UINT16                    HeaderLength;
	 *  /// A 16-bit checksum of the firmware volume header. A valid header sums to zero.
	 *  UINT16                    Checksum;
	 *  /// Offset, relative to the start of the header, of the extended header
	 *  /// (EFI_FIRMWARE_VOLUME_EXT_HEADER) or zero if there is no extended header.
	 *  UINT16                    ExtHeaderOffset;
	 *  /// This field must always be set to zero.
	 *  UINT8                     Reserved[1];
	 *  /// Set to 2. Future versions of this specification may define new header fields and will
	 *  /// increment the Revision field accordingly.
	 *  UINT8                     Revision;
	 *  /// An array of run-length encoded FvBlockMapEntry structures. The array is
	 *  /// terminated with an entry of {0,0}.
	 *  EFI_FV_BLOCK_MAP_ENTRY    BlockMap[1];
	 * } EFI_FIRMWARE_VOLUME_HEADER;
	 */
	private byte[] zeroVector;
	private String fileSystemGuid;
	private long fvLength;
	private int signature;
	private int attributes;
	private short headerLength;
	private short checksum;
	private short extHeaderOffset;
	private byte reserved;
	private byte revision;
	private List<EFIFVBlockMapEntry> blockMap;
	
	/*
	 * /// Extension header pointed by ExtHeaderOffset of volume header.
	 * typedef struct {
	 *   /// Firmware volume name.
	 *   EFI_GUID    FvName;
	 *   /// Size of the rest of the extension header, including this structure.
	 *   UINT32      ExtHeaderSize;
	 * } EFI_FIRMWARE_VOLUME_EXT_HEADER;
	 */
	private String fvName;
	private int extHeaderSize;
	
	private boolean checksumValid;
	private long basePointer;
	private int alignment;
	
	private List<EFIFirmwareFile> files;
	
	private void parseHeader(BinaryReader reader) throws IOException {
		// from https://github.com/al3xtjames/ghidra-firmware-utils/blob/master/src/main/java/firmware/uefi_fv/UEFIFirmwareVolumeHeader.java
		// check header 16-bit sums to 0
		reader.setPointerIndex(basePointer);
		int headerSum = 0;
		for (int i = 0; i < headerLength; i += 2) {
			headerSum += reader.readNextShort();
		}
		checksumValid = (headerSum & 0xFFFF) == 0;
		
		
		
		// extended header
		if (extHeaderOffset > 0 && revision == 2) {
			reader.setPointerIndex(basePointer + extHeaderOffset);
			fvName = EFIGUIDs.bytesToGUIDString(
					reader.readNextByteArray(EFIGUIDs.EFI_GUID_LEN));
			extHeaderSize = reader.readNextInt();
			reader.setPointerIndex(basePointer + extHeaderOffset + extHeaderSize);
		} else {
			reader.setPointerIndex(basePointer + headerLength);
		}
		
//		int alignAttribute = (attributes & EFI_FVB2_ALIGNMENT) >> 4;
//		alignment = 1 << alignAttribute;
	}
	
	private void readBlockMap(BinaryReader reader, long headerEnd) throws IOException {
		while (reader.getPointerIndex() <= headerEnd) {
			int numBlocks = reader.readNextInt();
			int length = reader.readNextInt();
			if (numBlocks == 0 && length == 0) {
				return;
			}
			blockMap.add(new EFIFVBlockMapEntry(numBlocks, length));
		}
	}
	
	private void readFileSystems(BinaryReader reader, long fvEnd) throws IOException {
		long curIdx = reader.getPointerIndex();
		reader.align(EFI_FV_OFFSET);
		while (curIdx < fvEnd) {
			if (Arrays.equals(reader.readByteArray(curIdx, EFIFirmwareFile.EFI_FF_HEADER_LEN), FREE_SPACE_HEADER)) {
				// free space, skip until end
//				reader.setPointerIndex(fvEnd);
				while (curIdx < fvEnd) {
					// read until the end of the free space
					int nextInt = reader.readNextInt();
					if (nextInt != 0xffffffff) {
						reader.setPointerIndex(reader.getPointerIndex() - 4);
						break;
					}
					curIdx = reader.getPointerIndex();
				}
				if (curIdx >= fvEnd) {
					break;
				}
			}
			try {
				files.add(new EFIFirmwareFile(reader));
			} catch (IOException e) {
				// what should we do if there's a corrupt/non-UEFI file?
				reader.setPointerIndex(fvEnd);
				break;
			}
			reader.align(EFI_FV_OFFSET);
			curIdx = reader.getPointerIndex();
		}
	}
	
	/**
	 * 
	 * @param reader A BinaryReader with its index at the start of this FV header 
	 * @throws IOException if an exception occurs while reading from the reader
	 */
	public EFIFirmwareVolume(BinaryReader reader, boolean readFileSystem) throws IOException {
		// is there some better way to do this? please tell me there is
		Arrays.fill(FREE_SPACE_HEADER, (byte)0xff);
		
		basePointer = reader.getPointerIndex();
		files = new ArrayList<>();
		// header
		zeroVector = reader.readNextByteArray(ZERO_VECTOR_LEN);
		fileSystemGuid = EFIGUIDs.bytesToGUIDString(
				reader.readNextByteArray(EFIGUIDs.EFI_GUID_LEN));
		fvLength = reader.readNextLong();
		signature = reader.readNextInt();
		attributes = reader.readNextInt();
		headerLength = reader.readNextShort();
		checksum = reader.readNextShort();
		extHeaderOffset = reader.readNextShort();
		reserved = reader.readNextByte();
		revision = reader.readNextByte();

		blockMap = new ArrayList<>();
		readBlockMap(reader, basePointer + headerLength);
				
		parseHeader(reader);
		
		if (readFileSystem) {
			long fvEnd = basePointer + fvLength;
			readFileSystems(reader, fvEnd);
			
			// in case malformed files have read past the FirmwareVolume end 
			reader.setPointerIndex(fvEnd);
		}
	}
	
	public EFIFirmwareVolume(BinaryReader reader) throws IOException {
		this(reader, true);
	}
	
	public EFIFirmwareVolume(Memory memory, ProgramFragment fragment) throws IOException {
		this(new BinaryReader(new MemoryByteProvider(
				memory, fragment.getFirstRange().getAddressSpace()), 
				GhidraLittleEndianDataConverter.INSTANCE, 
				fragment.getMinAddress().getOffset()), false);
	}
	
	public long getBasePointer() {
		return basePointer;
	}
	
	public long getLength() {
		return fvLength;
	}
	
	public String getFileSystemGUID() {
		return fileSystemGuid;
	}
	
	public String getNameGUID() {
		return fvName == null ? fileSystemGuid : fvName;
	}
	
	public List<EFIFirmwareFile> getFiles() {
		return files;
	}
	
	public long getHeaderLength() {
		return headerLength;
	}
	
	public boolean isChecksumValid() {
		return checksumValid;
	}
}
