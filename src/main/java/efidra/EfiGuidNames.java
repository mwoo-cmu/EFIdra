package efidra;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.HexFormat;

import org.postgresql.shaded.com.ongres.scram.common.bouncycastle.pbkdf2.Arrays;

import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvValidationException;

public class EFIGUIDNames {
	private HashMap<String, String> guids;
	
	public static String bytesToGUIDString(byte[] bytes) {
		// 16 bytes from 4 + 2 + 2 + 8
		// bytes should be a byte array from ByteProvider.readBytes(idx, 16)
		// can also be from BinaryReader.readByteArray or BinaryReader.readNextByteArray
		HexFormat formatter = HexFormat.of();
		return new StringBuilder(formatter.formatHex(Arrays.copyOfRange(bytes, 0, 4)))
				.append("-")
				.append(formatter.formatHex(Arrays.copyOfRange(bytes, 4, 6)))
				.append("-")
				.append(formatter.formatHex(Arrays.copyOfRange(bytes, 6, 8)))
				.append("-")
				.append(formatter.formatHex(Arrays.copyOfRange(bytes, 8, 10)))
				.append("-")
				.append(formatter.formatHex(Arrays.copyOfRange(bytes, 10, 16))).toString();
	}
	
	public EFIGUIDNames(boolean loadDefaults) {
		guids = new HashMap<>();
		if (loadDefaults) {
			parseGUIDsFromURL("https://fwupd.org/lvfs/shards/export/csv");
		}
	}

	public EFIGUIDNames() {
		this(true);
	}
	
	public String getReadableName(String guid) {
		return guids.get(guid);
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
	 */
	public void parseGUIDsFromURL(String link) {
		// may need to be public to be accessible by scripts
		// want a script to allow users to specify a file path or url
		try {
			URL url = new URL(link);
			BufferedReader buffer = new BufferedReader(new InputStreamReader(url.openStream()));
			parseGUIDsFromCSV(buffer);
		} catch (MalformedURLException e) {
			// TODO display to user somehow
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CsvValidationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/**
	 * Reads in the CSV data from a given file path and adds them to the 
	 * object's internal HashMap mapping GUIDs to their readable names
	 * 
	 * @param path	the path to the file on the file system
	 */
	public void parseGUIDsFromFile(String path) {
		FileReader reader;
		try {
			reader = new FileReader(path);
			parseGUIDsFromCSV(reader);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CsvValidationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
