package efidra;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;

public class EFIFirmwareVolume {
	private class EFIFVBlockMap {
		private int numBlocks;
		private int length;
		private List<byte[]> blocks;
		
		public EFIFVBlockMap(BinaryReader reader, long fvEnd) throws IOException {
			blocks = new ArrayList<>();
			while (readNextBlockMapEntry(reader, fvEnd)) {
				for (int i = 0; i < numBlocks; i++) {
					blocks.add(reader.readNextByteArray(length));
				}
			}
		}
		
		private boolean readNextBlockMapEntry(BinaryReader reader, long fvEnd) throws IOException {
			/*
			 * typedef struct {
			 *   /// The number of sequential blocks which are of the same size.
			 *   UINT32    NumBlocks;
			 *   /// The size of the blocks.
			 *   UINT32    Length;
			 * } EFI_FV_BLOCK_MAP_ENTRY;
			 */
			numBlocks = reader.readNextInt();
			length = reader.readNextInt();
			return numBlocks != 0 && length != 0 && reader.getPointerIndex() <= fvEnd;
		}
	}
	
	private static final int ZERO_VECTOR_LEN = 16;
	// from zeroVector + fileSystemGuid + fvLength
	public static final int EFI_SIG_OFFSET = 16 + 16 + 8;
	
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
	private EFIFVBlockMap blockMap;
	
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
	
	/**
	 * 
	 * @param reader A BinaryReader with its index at the start of this FV header 
	 * @throws IOException if an exception occurs while reading from the reader
	 */
	public EFIFirmwareVolume(BinaryReader reader) throws IOException {
		long basePointer = reader.getPointerIndex();
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
				
		// https://github.com/al3xtjames/ghidra-firmware-utils/blob/master/src/main/java/firmware/uefi_fv/UEFIFirmwareVolumeHeader.java
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
		
		long fvEnd = basePointer + fvLength;
		blockMap = new EFIFVBlockMap(reader, fvEnd);
		
		reader.setPointerIndex(fvEnd);
	}
}
