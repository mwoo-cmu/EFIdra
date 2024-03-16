/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package efidra;

import java.awt.BorderLayout;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.regex.Pattern;

import javax.swing.JPanel;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import generic.jar.ResourceFile;
import ghidra.app.analyzers.FunctionStartPostAnalyzer;
import ghidra.app.analyzers.FunctionStartPreFuncAnalyzer;
import ghidra.app.analyzers.PortableExecutableAnalyzer;
import ghidra.app.plugin.core.disassembler.EntryPointAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptLoadException;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.JavaScriptProvider;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.mz.DOSHeader;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Integer3DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Group;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class efidraAnalyzer extends AbstractAnalyzer {
	public static final String LABEL_EFI_GUID = "EFI_GUID";
	public static final String LABEL_EFI_FV_BLOCK_MAP_ENTRY = "EFI_FV_BLOCK_MAP_ENTRY";
	public static final String LABEL_EFI_FIRMWARE_VOLUME_HEADER = "EFI_FIRMWARE_VOLUME_HEADER";
	public static final String LABEL_EFI_FFS_INTEGRITY_CHECK = "EFI_FFS_INTEGRITY_CHECK";
	public static final String LABEL_EFI_FFS_FILE_HEADER = "EFI_FFS_FILE_HEADER";
	public static final String LABEL_EFI_FFS_FILE_HEADER2 = "EFI_FFS_FILE_HEADER2";
	public static final String LABEL_EFI_COMMON_SECTION_HEADER = "EFI_COMMON_SECTION_HEADER";
	public static final String LABEL_EFI_COMMON_SECTION_HEADER2 = "EFI_COMMON_SECTION_HEADER2";
	
	public static final String NVRAM_GUID = "CEF5B9A3-476D-497F-9FDC-E98143E0422C";
	
	private Address programBase;
	private EFIGUIDs guids;
	public static EFIdraParserScript parser;

	public efidraAnalyzer() {

		// TODO: Name the analyzer and give it a description.

		super("EFIdra UEFI Analyzer", "Analyze a loaded UEFI ROM", AnalyzerType.BYTE_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {

		// TODO: Return true if analyzer should be enabled by default

		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {

		// TODO: Examine 'program' to determine of this analyzer should analyze it.  Return true
		// if it can.
		
		

		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {

		// TODO: If this analyzer has custom options, register them here

//		options.registerOption("Option name goes here", false, null,
//			"Option description goes here");
	}
	
	private void parseNVRAMStructures(ProgramFragment programFragment, Listing listing, Memory memory) throws IOException, CodeUnitInsertionException {
		Address fragBase = programFragment.getMinAddress();
		BinaryReader fragReader = new BinaryReader(
				new MemoryByteProvider(memory, fragBase), true);
		// ensure that the first 4 bytes are the "NVAR" signature
		if (fragReader.peekNextInt() != EFINVAREntry.EFI_NVAR_SIGNATURE) {
			return;
		}
		
		// set up first "NVAR" string
		listing.createData(fragBase, StringDataType.dataType, 4);
	}
	
	private void getParser(String name) throws FileNotFoundException, GhidraScriptLoadException {
		// GhidraScript
		ResourceFile scriptFile = GhidraScriptUtil.findScriptByName(name);
		// not GhidraScript, .java file in data/rom_formats directory
		if (scriptFile == null) {
			scriptFile = Application.getModuleDataFile(
					EFIdraROMFormatLoader.EFI_ROM_FORMATS_DIR + "/" + name);
		}
		PrintWriter writer = new PrintWriter(System.out);
		GhidraScriptProvider provider;
		GhidraScript script;
		provider = GhidraScriptUtil.getProvider(scriptFile);
		// if can't find a provider for the script, create a new java one to run it
		if (provider == null)
			provider = new JavaScriptProvider();
		script = provider.getScriptInstance(scriptFile, writer);
		parser = (EFIdraParserScript) script;
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		EFIdraROMFormatLoader.init(program);
		guids = new EFIGUIDs();
		programBase = program.getImageBase();
		Listing listing = program.getListing();
		ProgramModule rootModule = listing.getDefaultRootModule();
		Memory memory = program.getMemory();
		
		// probably try to give options to select the parser, along with an "all" option
		// "all" tries everything until one works without error?
		
		try {
			getParser("PiFirmwareParser.java");
			parser.parseROM(program);
		} catch (FileNotFoundException | GhidraScriptLoadException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		analyzeExecutablesRecursive(rootModule, program, monitor, log);
		
		return true;
	}
	
	public void analyzeExecutablesRecursive(ProgramModule module, Program program, 
			TaskMonitor monitor, MessageLog log) 
			throws CancelledException {
//		PortableExecutableAnalyzer peAnalyzer = new PortableExecutableAnalyzer();
		FunctionStartPreFuncAnalyzer funcPreAnalyzer = new FunctionStartPreFuncAnalyzer();
		FunctionStartPostAnalyzer funcPostAnalyzer = new FunctionStartPostAnalyzer();
		EntryPointAnalyzer entryAnalyzer = new EntryPointAnalyzer();
		Disassembler disassembler = Disassembler.getDisassembler(program, monitor, DisassemblerMessageListener.CONSOLE);
		Memory memory = program.getMemory();
		Listing listing = program.getListing();
		for (Group programItem : module.getChildren()) {
			if (programItem instanceof ProgramFragment) {
				ProgramFragment fragment = (ProgramFragment) programItem;
				if (!(fragment.getName().startsWith("Header")) && parser.isExecutable(program, fragment)) {
					
//					peAnalyzer.added(program, fragment, monitor, log);
					// create a new root module for this file, containing all of its data
					try {
						ProgramModule[] parents = fragment.getParents();
						String exeName = parents[parents.length - 1].getName().split(Pattern.quote("(0x"))[0] 
								+ fragment.getName();
						ProgramModule progRoot = listing.createRootModule(exeName);
						Address exeBase = fragment.getMinAddress().add(
								parser.offsetToExecutable(program, fragment));
						ByteProvider provider = new MemoryByteProvider(memory, exeBase);
						long baseOffs = exeBase.getOffset();
//						MemoryBlock progBlock = memory.createInitializedBlock(exeName, 
////								program.getImageBase(),
//								exeBase,
//								provider.getInputStream(0),
//								fragment.getMaxAddress().getOffset() - baseOffs, 
//								monitor, true);
						
						ExecutableSectionAnalyzers.runPEAnalyzer(program, progRoot, 
								disassembler, provider, exeName, exeBase, log, monitor);
//						entryAnalyzer.added(program, fragment, monitor, log);
//						funcPostAnalyzer.added(program, fragment, monitor, log);
						
						provider.close();
					} catch (DuplicateNameException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
//					} catch (LockException e) {
//						// TODO Auto-generated catch block
//						e.printStackTrace();
//					} catch (MemoryConflictException e) {
//						// TODO Auto-generated catch block
//						e.printStackTrace();
//					} catch (AddressOverflowException e) {
//						// TODO Auto-generated catch block
//						e.printStackTrace();
//					} catch (IllegalArgumentException e) {
//						// TODO Auto-generated catch block
//						e.printStackTrace();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			} else if (programItem instanceof ProgramModule) {
				analyzeExecutablesRecursive((ProgramModule) programItem, program, monitor, log);
			}
		}
		
	}
}
