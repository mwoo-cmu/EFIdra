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
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class EFIdraROMFormatLoader {
	public static final String EFI_ROM_FORMATS_DIR = "rom_formats";
	private static final String EXTENSIONS_JSON = "extensions.json";
	private static final char ARRAY_OPEN = '[';
	private static final char ARRAY_CLOSE = ']';
	private static final char POINTER = '*';
	
	private static File formatsDir;
	private static DataTypeManager dtm; 
	public static HashMap<String, DataType> dataTypes = new HashMap<>();
	public static List<EFIdraExecutableAnalyzerScript> execAnalyzers = new ArrayList<>();
	public static HashMap<String, EFIdraParserScript> parsers = new HashMap<>();
	
	/**
	 * Adds all of the Ghidra built-in data types from the given program
	 * @param program The program from which to load in all of the built-in 
	 * data types
	 */
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
	
	/**
	 * initializes the ROM format loader for the given program by reading in 
	 * all of the ROM formats from the default directory (data/rom_formats) and
	 * adding all of the analyzer and parser scripts as defined in 
	 * data/extensions.json
	 * @param program The program to load data structures into
	 * @param monitor The monitor for this initialization job
	 */
	public static void init(Program program, TaskMonitor monitor) {
		if (formatsDir == null) {
			try {
				formatsDir = Application.getModuleDataSubDirectory(EFI_ROM_FORMATS_DIR).getFile(true);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			addGhidraDataTypes(program);
			loadROMFormats(program, monitor);
			loadExtensionScripts();
		}
	}
	
	/**
	 * Parses an array data type recursively, to create an arbitrary number of
	 * arrays from the String type name. Note that the sizes of arrays must be 
	 * specified for proper construction of the array type.
	 * @param type the String of the array type (e.g. int[4])
	 * @return the ArrayDataType, or the resolved type if it is not an array
	 */
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
	
	/**
	 * Parses a pointer data type recursively, to create an arbitrary number of
	 * pointers from a String type name
	 * @param type the String of the pointer type (e.g. "void*")
	 * @return The PointerDataType, or the resolved type if it is not a pointer
	 */
	private static DataType parsePointerRecursive(String type) {
		if (type.charAt(type.length() - 1) == POINTER) {
			int endIdx = type.lastIndexOf(POINTER);
			String subtype = type.substring(0, endIdx);
			DataType dType = parsePointerRecursive(subtype);
			return new PointerDataType(dType);
		}
		return dataTypes.get(type);
	}
	
	/**
	 * Parses a StructureDataType from the given JSON array of members with the
	 * given name, as defined in the JSON structure specification
	 * @param name The name of the data type to parse
	 * @param members The members of the data type, in order
	 * @return The DataType generated from reading in the members
	 */
	public static DataType parseDataType(String name, JSONArray members) {
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
	
	/**
	 * Parses a JSON object representing an enumeration in the JSON structure
	 * specification
	 * @param name the name of the enum type to add
	 * @param enumMembers the JSONObject representing the enum members
	 * @return the EnumDataType representation of the enum
	 */
	public static EnumDataType parseEnumType(String name, JSONObject enumMembers) {
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
	
	/**
	 * Loads in structures from a given JSON file
	 * @param file the JSON file to load in structures from 
	 */
	private static void loadJSON(File file) {
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
						dataTypes.put(name, parseDataType(name, members));
					}
					JSONObject enumMembers = (JSONObject) struct.get("enum");
					if (enumMembers != null) {
						if (dataTypes.containsKey(name)) {
							Msg.info(null, "Duplicate structure name " + name
									+ ". Second occurrence in " + file.getName());									
						}
						dataTypes.put(name, parseEnumType(name, enumMembers));
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
	
	/**
	 * Loads in a specific JSON file ROM format from the default ROM format
	 * directory into the given program
	 * @param program The program to which the data types read from the ROM 
	 * format JSON should be added
	 * @param jsonFile The filename of the JSON ROM format file to load in
	 * @throws FileNotFoundException if the file was not found in the ROM
	 * format directory
	 */
	public static void loadROMFormat(Program program, String jsonFile) throws FileNotFoundException {
		ResourceFile f = Application.getModuleDataFile(EFI_ROM_FORMATS_DIR + "/" + jsonFile);
		loadJSON(f.getFile(true));
	}
	
	/**
	 * Loads all ROM formats in the default format directory (data/rom_formats)
	 * into the program using the given monitor
	 * @param program The program to which the data types read from ROM formats
	 * should be added
	 * @param monitor The monitor for this load task
	 */
	public static void loadROMFormats(Program program, TaskMonitor monitor) {
		dtm = program.getDataTypeManager();
		for (File file : formatsDir.listFiles()) {
			if (file.isFile()) {
				String fName = file.getName();
				if (fName.endsWith(".json")) {
					loadJSON(file);
				} else if (fName.endsWith(".gdt")) {
					try {
						FileDataTypeManager fdtm = FileDataTypeManager.openFileArchive(file, false);
						Msg.info(null, fdtm.getPointer(VoidDataType.dataType).getLength());
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
//				} else if (fName.endsWith(".java")) {
//					try {
//						addUserScript(file);
//					} catch (GhidraScriptLoadException e) {
//						// TODO Auto-generated catch block
//						e.printStackTrace();
//					} catch (IOException e) {
//						// TODO Auto-generated catch block
//						e.printStackTrace();
//					}
				}
			}
		}
	}
	
	/**
	 * Loads in all of the extension scripts for executable analysis and ROM 
	 * parsing as defined in the data/extensions.json file
	 */
	public static void loadExtensionScripts() {
		try {
			JSONObject extData = (JSONObject) (new JSONParser().parse(new FileReader(
				Application.getModuleDataFile(EXTENSIONS_JSON).getFile(true))));
			// note that technically these can just be coalesced into one, but 
			// is kept separate for clarity
			JSONArray analyzerNames = (JSONArray) extData.get("ExecutableAnalyzers");
			for (Object name : analyzerNames) {
				addUserScript((String) name);
			}
			JSONArray parserNames = (JSONArray) extData.get("Parsers");
			for (Object name : parserNames) {
				addUserScript((String) name);
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
		} catch (GhidraScriptLoadException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
//	
//	public static void addUserScript(File file) throws IOException, GhidraScriptLoadException {
//		// assumes that the file is can't be retrieved by name
//		ResourceFile scriptFile = new ResourceFile(file);
//		PrintWriter writer = new PrintWriter(System.out);
//		GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
//		// if can't find a provider for the script, create a new java one to run it
//		GhidraScript script;
//		if (provider == null) {
//			provider = new JavaScriptProvider();
//		}
//		provider.createNewScript(scriptFile, "EFIdra Scripts");
//		script = provider.getScriptInstance(scriptFile, writer);
//		if (script instanceof EFIdraExecutableAnalyzerScript) {
//			execAnalyzers.add((EFIdraExecutableAnalyzerScript) script);
//		} else if (script instanceof EFIdraParserScript) {
//			parsers.put(file.getName(), (EFIdraParserScript) script);
//		}
//	}
	
	/**
	 * Adds a GhidraScript specified by name as either an executable analyzer 
	 * or a ROM parser, depending on which class it extends. Does nothing if 
	 * the specified script does not extend either EFIdraParserScript or 
	 * EFIdraExecutableAnalyzerScript.
	 * @param name The name of the script to add
	 * @throws GhidraScriptLoadException if the script could not be loaded
	 * @throws IOException if the script could not be read
	 */
	public static void addUserScript(String name) throws GhidraScriptLoadException, IOException {
		ResourceFile scriptFile = GhidraScriptUtil.findScriptByName(name);
		// not GhidraScript, .java file in data/rom_formats directory
		if (scriptFile == null) {
			scriptFile = Application.getModuleDataFile(
					EFIdraROMFormatLoader.EFI_ROM_FORMATS_DIR + "/" + name);
//			addUserScript(scriptFile.getFile(true));
//			return;
		}
		PrintWriter writer = new PrintWriter(System.out);
		GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
		// if can't find a provider for the script, create a new java one to run it
		GhidraScript script = provider.getScriptInstance(scriptFile, writer);
		if (script instanceof EFIdraExecutableAnalyzerScript) {
			execAnalyzers.add((EFIdraExecutableAnalyzerScript) script);
		} else if (script instanceof EFIdraParserScript) {
			parsers.put(name, (EFIdraParserScript) script);
		}
	}

	/**
	 * Gets the DataType object of the given type name, loaded in from the ROM
	 * format data types
	 * @param typeName The name of the type to retrieve
	 * @return the DataType object defining the given type name
	 */
	public static DataType getType(String typeName) {
		DataType type = dataTypes.get(typeName);
		if (type == null) {
			type = dtm.getDataType(typeName);
		}
		return type;
	}
}
