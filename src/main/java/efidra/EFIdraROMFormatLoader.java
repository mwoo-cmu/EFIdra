package efidra;

import java.awt.BorderLayout;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;

import javax.swing.JPanel;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import ghidra.framework.Application;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class EFIdraROMFormatLoader {
	private static final String EFI_ROM_FORMATS_DIR = "rom_formats";
	
	private static File formatsDir;
	public static HashMap<String, DataType> dataTypes;
	
	private static void addGhidraDataTypes(Program program) {
		Iterator<DataType> iter = program.getDataTypeManager().getAllDataTypes();
		// for some reason only 5...
		while (iter.hasNext()) {
			DataType dType = iter.next();
			dataTypes.put(dType.getName(), dType);
		}
		Iterator<DataType> btIter = BuiltInDataTypeManager.getDataTypeManager().getAllDataTypes();
		while (btIter.hasNext()) {
			DataType dType = btIter.next();
			dataTypes.put(dType.getName(), dType);
		}
	}
	
	public static void init(Program program) {
		if (formatsDir == null || dataTypes == null) {
			try {
				formatsDir = Application.getModuleDataSubDirectory(EFI_ROM_FORMATS_DIR).getFile(true);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			dataTypes = new HashMap<>();
			addGhidraDataTypes(program);
			loadROMFormats(program);
		}
	}
	
	public static void loadROMFormats(Program program) {
		for (File file : formatsDir.listFiles()) {
			if (file.isFile()) {
				try {
					JSONObject format = (JSONObject) (new JSONParser().parse(new FileReader(file)));
					JSONArray structures = (JSONArray) format.get("structures");
					if (structures != null) {
						for (Object structObj : structures) {
							JSONObject struct = (JSONObject) structObj;
							String name = (String) struct.get("name");
							JSONArray members = (JSONArray) struct.get("members");
							if (dataTypes.containsKey(name)) {
								Msg.info(null, "Duplicate structure name " + name
										+ ". Second occurrence in " + file.getName());
							}
							dataTypes.put(name, null);
						}
					} else {
						Msg.info(null, "No structures found in " + file.getName());
					}
				} catch (FileNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (ParseException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					JPanel panel = new JPanel(new BorderLayout());
					Msg.showError(null, panel, "EFIdra Analyzer", 
							"Error parsing format JSON from " + file.getName());
				}
			}
		}
	}
}
