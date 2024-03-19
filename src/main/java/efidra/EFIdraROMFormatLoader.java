package efidra;

import java.awt.BorderLayout;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import javax.swing.JPanel;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptLoadException;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.JavaScriptProvider;
import ghidra.framework.Application;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class EFIdraROMFormatLoader {
	public static final String EFI_ROM_FORMATS_DIR = "rom_formats";
	private static final char ARRAY_OPEN = '[';
	private static final char ARRAY_CLOSE = ']';
	private static final char POINTER = '*';
	
	private static File formatsDir;
	public static HashMap<String, DataType> dataTypes;
	public static List<EFIdraExecutableAnalyzerScript> execAnalyzers;
	public static HashMap<String, EFIdraParserScript> parsers;
	
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
	
	public static void init(Program program, TaskMonitor monitor) {
		if (formatsDir == null || dataTypes == null) {
			try {
				formatsDir = Application.getModuleDataSubDirectory(EFI_ROM_FORMATS_DIR).getFile(true);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			dataTypes = new HashMap<>();
			execAnalyzers = new ArrayList<>();
			parsers = new HashMap<>();
			addGhidraDataTypes(program);
			loadROMFormats(program, monitor);
		}
	}
	
	private static DataType parseArrayRecursive(String type) {
		if (type.charAt(type.length() - 1) == ARRAY_CLOSE) {
			int arrayIdx = type.lastIndexOf(ARRAY_OPEN);
			String subtype = type.substring(0, arrayIdx);
			// strip off the brackets and convert to int
			int length = Integer.parseInt(type.substring(arrayIdx + 1, type.length() - 1));
			DataType dType = parseArrayRecursive(subtype);
			return new ArrayDataType(dType, length, dType.getLength());
		}
		return dataTypes.get(type);
	}
	
	private static DataType parsePointerRecursive(String type) {
		if (type.charAt(type.length() - 1) == POINTER) {
			int endIdx = type.lastIndexOf(POINTER);
			String subtype = type.substring(0, endIdx);
			DataType dType = parsePointerRecursive(subtype);
			return new PointerDataType(dType);
		}
		return dataTypes.get(type);
	}
	
	public static DataType parseDataType(String name, JSONArray members, DataTypeManager dtm) {
		StructureDataType sdt = new StructureDataType(name, 0, dtm);
		for (Object memberObj : members) {
			JSONObject member = (JSONObject) memberObj;
			String type = (String) member.get("type");
			Long sizeField = (Long) member.get("size");
			int size = 0;
			if (sizeField != null)
				size = sizeField.intValue();
			// fallback in case the type queried is null or not in the HashMap
			DataType dType = Undefined.getUndefinedDataType(size);
			if (type != null) {
				DataType loadedDataType; 
				if (type.charAt(type.length() - 1) == POINTER) {
					loadedDataType = parsePointerRecursive(type);
				} else {
					loadedDataType = parseArrayRecursive(type);
				}
				// if non-array, will return dataTypes.get(type)
				if (loadedDataType != null) {
					dType = loadedDataType;
				}
			}
			if (size > 0) {
				sdt.add(dType, size, (String) member.get("name"), 
						(String) member.get("comment"));
			} else {
				sdt.add(dType, (String) member.get("name"), (String) member.get("comment"));				
			}
		}
		return sdt;
	}
	
	public static DataType parseDataType(String name, JSONArray members) {
		return parseDataType(name, members, null);
	}
	
	public static EnumDataType parseEnumType(String name, JSONObject enumMembers, DataTypeManager dtm) {
		// determine how many bytes are needed to hold all enum values
		long maxVal = (long) Collections.max(enumMembers.values());
		int nBytes = 1;
		// ghidra's EnumDataType takes 1, 2, 4, or 8 bytes
		for (; nBytes <= 8; nBytes *= 2) {
			long byteMax = 1 << (nBytes * 8);
			if (byteMax >= maxVal) {
				break;
			}
		}
		EnumDataType edt = new EnumDataType(CategoryPath.ROOT, name, nBytes, dtm);
		for (Object key : enumMembers.keySet()) {
			edt.add((String) key, (long) enumMembers.get(key));
		}
		return edt;
	}
	
	public static EnumDataType parseEnumType(String name, JSONObject enumMembers) {
		return parseEnumType(name, enumMembers, null);
	}	
	
	private static void loadJSON(File file, DataTypeManager dtm) {
		try {
			JSONObject format = (JSONObject) (new JSONParser().parse(new FileReader(file)));
			JSONArray structures = (JSONArray) format.get("structures");
			if (structures != null) {
				for (Object structObj : structures) {
					JSONObject struct = (JSONObject) structObj;
					String name = (String) struct.get("name");
					JSONArray members = (JSONArray) struct.get("members");
					if (members != null) {
						if (dataTypes.containsKey(name)) {
							Msg.info(null, "Duplicate structure name " + name
									+ ". Second occurrence in " + file.getName());
						}
						dataTypes.put(name, parseDataType(name, members, dtm));
					}
					JSONObject enumMembers = (JSONObject) struct.get("enum");
					if (enumMembers != null) {
						if (dataTypes.containsKey(name)) {
							Msg.info(null, "Duplicate structure name " + name
									+ ". Second occurrence in " + file.getName());									
						}
						dataTypes.put(name, parseEnumType(name, enumMembers, dtm));
					}
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
	
	public static void loadROMFormat(Program program, String jsonFile) throws FileNotFoundException {
		ResourceFile f = Application.getModuleDataFile(EFI_ROM_FORMATS_DIR + "/" + jsonFile);
		loadJSON(f.getFile(true), program.getDataTypeManager());
	}
	
	public static void loadROMFormats(Program program, TaskMonitor monitor) {
		DataTypeManager dtm = program.getDataTypeManager();
		for (File file : formatsDir.listFiles()) {
			if (file.isFile()) {
				String fName = file.getName();
				if (fName.endsWith(".json")) {
					loadJSON(file, dtm);
				} else if (fName.endsWith(".gdt")) {
					try {
						FileDataTypeManager fdtm = FileDataTypeManager.openFileArchive(file, false);
						List<DataType> fDataTypes = new ArrayList<>();
						fdtm.getAllDataTypes(fDataTypes);
						dtm.addDataTypes(fDataTypes, 
								DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER, 
								monitor);
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (CancelledException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				} else if (fName.endsWith(".java")) {
					try {
						addUserScript(file);
					} catch (GhidraScriptLoadException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			}
		}
	}
	
	public static void addUserScript(File file) throws GhidraScriptLoadException {
		ResourceFile scriptFile = new ResourceFile(file);
		PrintWriter writer = new PrintWriter(System.out);
		GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
		// if can't find a provider for the script, create a new java one to run it
		if (provider == null)
			provider = new JavaScriptProvider();
		GhidraScript script = provider.getScriptInstance(scriptFile, writer);
		if (script instanceof EFIdraExecutableAnalyzerScript) {
			execAnalyzers.add((EFIdraExecutableAnalyzerScript) script);
		} else if (script instanceof EFIdraParserScript) {
			parsers.put(file.getName(), (EFIdraParserScript) script);
		}
	}
	
	public static void addUserScript(String name) throws FileNotFoundException, GhidraScriptLoadException {
		ResourceFile scriptFile = GhidraScriptUtil.findScriptByName(name);
		// not GhidraScript, .java file in data/rom_formats directory
		if (scriptFile == null) {
			scriptFile = Application.getModuleDataFile(
					EFIdraROMFormatLoader.EFI_ROM_FORMATS_DIR + "/" + name);
		}
		PrintWriter writer = new PrintWriter(System.out);
		GhidraScriptProvider provider;
		provider = GhidraScriptUtil.getProvider(scriptFile);
		// if can't find a provider for the script, create a new java one to run it
		if (provider == null)
			provider = new JavaScriptProvider();
		GhidraScript script = provider.getScriptInstance(scriptFile, writer);
		if (script instanceof EFIdraExecutableAnalyzerScript) {
			execAnalyzers.add((EFIdraExecutableAnalyzerScript) script);
		} else if (script instanceof EFIdraParserScript) {
			parsers.put(name, (EFIdraParserScript) script);
		}
	}

	public static DataType getType(String typeName) {
		return dataTypes.get(typeName);
	}
}
