package efidra;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URL;
import java.util.HashMap;
import java.util.HexFormat;

import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvValidationException;

import ghidra.framework.Application;
import ghidra.util.Msg;

public class EFIGUIDs {
	public static final int EFI_GUID_LEN = 16;
	public static final int EFI_GUID_DATA4_LEN = 8;
	
	private static HashMap<String, String> guids = new HashMap<>();
	private static final String GUIDS_CSV = "guids.csv";
	
	public static String bytesToGUIDString(byte[] bytes) {
		// 16 bytes from 4 + 2 + 2 + 8
		// bytes should be a byte array from ByteProvider.readBytes(idx, 16)
		// can also be from BinaryReader.readByteArray or BinaryReader.readNextByteArray
		HexFormat formatter = HexFormat.of().withUpperCase();
		// necessary because GUIDs use little endian uint32_t and uint16_t
		// sadly, this is the least disgusting way I could find to do this, which is wild.
		int data1 = (bytes[0] & 0xff) + (0xff00 & (bytes[1] << 8)) + 
				(0xff0000 & (bytes[2] << 16)) + (0xff000000 & (bytes[3] << 24));
		short data2 = (short) ((bytes[4] & 0xff) + (0xff00 & (bytes[5] << 8)));
		short data3 = (short) ((bytes[6] & 0xff) + (0xff00 & (bytes[7] << 8)));		
		return new StringBuilder(
				formatter.toHexDigits(data1))
				.append("-")
				.append(formatter.toHexDigits(data2))
				.append("-")
				.append(formatter.toHexDigits(data3))
				.append("-")
				.append(formatter.formatHex(bytes, 8, 10))
				.append("-")
				.append(formatter.formatHex(bytes, 10, 16)).toString();
	}
	
	public EFIGUIDs(boolean loadDefaults) {
//		guids = new HashMap<>();
		if (loadDefaults) {
			try {
//				parseGUIDsFromURL("https://fwupd.org/lvfs/shards/export/csv");
				parseGUIDsFromFile(Application.getModuleDataFile(GUIDS_CSV).getFile(true));
			} catch (CsvValidationException | IOException e) {
				Msg.showError(e, null, "GUIDs Error", "Error loading default GUIDs");
				e.printStackTrace();
			}
		}
	}

	public EFIGUIDs() {
		this(guids.size() == 0);
	}
	
	public String getReadableName(String guid) {
		String name = guids.get(guid);
		if (name == null) {
			return guid;
		}
		return name;
	}
	
	public void clearGUIDs() {
		guids.clear();
	}
	
	/**
	 * Reads in the CSV data from a given Reader and adds them to the object's
	 * internal HashMap mapping GUIDs to their readable names
	 * 
	 * @param reader	The reader containing the CSV data to parse
	 * @throws CsvValidationException	if the CSVReader readNext fails
	 * @throws IOException	if the CSVReader could not be closed
	 */
	private void parseGUIDsFromCSV(Reader reader) throws CsvValidationException, IOException {
		CSVReader csvReader = new CSVReader(reader);
		String[] line;
		while ((line = csvReader.readNext()) != null) {
			guids.put(line[0], line[1]);
		}
		csvReader.close();
	}
	
	/**
	 * Reads in the CSV data from a given URL and adds them to the object's
	 * internal HashMap mapping GUIDs to their readable names
	 * 
	 * @param link	the URL from which to retrieve the GUIDs CSV
	 * @throws IOException 	If the URL cannot be opened or the CSVReader cannot be closed
	 * @throws CsvValidationException 	if the CSVReader encounters an error
	 */
	public void parseGUIDsFromURL(String link) throws IOException, CsvValidationException {
		// may need to be public to be accessible by scripts
		// want a script to allow users to specify a file path or url
		URL url = new URL(link);
		BufferedReader buffer = new BufferedReader(new InputStreamReader(url.openStream()));
		parseGUIDsFromCSV(buffer);
	}
	
	/**
	 * Reads in the CSV data from a given file path and adds them to the 
	 * object's internal HashMap mapping GUIDs to their readable names
	 * 
	 * @param path	the path to the file on the file system
	 * @throws IOException 	If the URL cannot be opened or the CSVReader cannot be closed
	 * @throws CsvValidationException 	if the CSVReader encounters an error 
	 */
	public void parseGUIDsFromFile(File file) throws CsvValidationException, IOException {
		FileReader reader = new FileReader(file);
		parseGUIDsFromCSV(reader);
	}
}
