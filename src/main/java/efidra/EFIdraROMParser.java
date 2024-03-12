package efidra;

import java.util.List;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.TaskMonitor;

public class EFIdraROMParser {
	public class EFIdraParserException extends Exception {

		public EFIdraParserException(String string) {
			// TODO Auto-generated constructor stub
			super(string);
		}
		
	}
	private String name;
	
	public EFIdraROMParser(JSONObject parserObj) throws EFIdraParserException {
		name = (String) parserObj.get("name");
		JSONArray layout = (JSONArray) parserObj.get("layout");
		if (layout == null) {
			// probably throw an exception
			throw new EFIdraParserException("no layout included in parser JSON");
		}
		for (Object obj : layout) {
			JSONObject struct = (JSONObject) obj;
			Object typeObj = struct.get("type");
			String structName = (String) struct.get("name");
			if (typeObj == null) {
				throw new EFIdraParserException("'type' key not included in struct " + structName);
			} else if (typeObj instanceof JSONArray) {
				JSONArray typeOptions = (JSONArray) typeObj;
				
			} else {
				JSONObject type = (JSONObject) typeObj;
			}
		}
	}
	
	public boolean load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log) {
		Address progBase = program.getImageBase();
		Memory memory = program.getMemory();
		
		Listing listing = program.getListing();
		ProgramModule rootModule = listing.getDefaultRootModule();
		
		return false;
	}
	
	public void analyze(Program program, AddressSetView set, TaskMonitor monitor, 
			MessageLog log) {
		
	}
}
