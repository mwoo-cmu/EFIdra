package efidra;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

public class EFINVAREntry {
	// "NVAR" stored in little endian
	public static final int EFI_NVAR_SIGNATURE = 0x5241564e;
	private static final int EFI_NVAR_RESERVED_BYTES = 3;
	private static final int EFI_NVAR_HEADER_SIZE = 10;
	
	private int signature;
	private short size;
	private byte reserved[];
	private byte attributes;
	
	private byte nvarData[];
	
	public EFINVAREntry(BinaryReader reader) throws IOException {
		signature = reader.readNextInt();
		size = reader.readNextShort();
		reserved = reader.readNextByteArray(EFI_NVAR_RESERVED_BYTES);
		attributes = reader.readNextByte();
		
		nvarData = reader.readNextByteArray(size - EFI_NVAR_HEADER_SIZE);
	}
}
