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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.regex.Pattern;

import javax.swing.JPanel;

import generic.jar.ResourceFile;
import ghidra.app.analyzers.FunctionStartPostAnalyzer;
import ghidra.app.analyzers.FunctionStartPreFuncAnalyzer;
import ghidra.app.plugin.core.disassembler.EntryPointAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptLoadException;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.JavaScriptProvider;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Group;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
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
	
	private static final String PARSER_OPTION = "Parser Script";
	private static final String ALL_PARSERS = "all";
	private static final String OFFSET_OPTION = "Image Offset (Hex)";
	
	public static final String NVRAM_GUID = "CEF5B9A3-476D-497F-9FDC-E98143E0422C";
	
	private Address programBase;
	private EFIGUIDs guids;
	public static EFIdraParserScript parser;
	private static long baseAddr;

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

		options.registerOption(PARSER_OPTION, ALL_PARSERS, null,
			"The name of the ROM parser script to use (should extend EFIdraParserScript)");
		
		// option for offset to where the image base should be?
//		options.registerOption(OFFSET_OPTION, "FE000000", null, 
//			"The base address at which this ROM image is loaded, in hexadecimal");
	}
	
	@Override
	public void optionsChanged(Options options, Program program) {
//		String offset = options.getString(OFFSET_OPTION, "0");
//		baseAddr = Long.parseUnsignedLong(offset, 16);
		
		String pScript = options.getString(PARSER_OPTION, ALL_PARSERS);
		if (ALL_PARSERS.equals(pScript)) {
			parser = null;
			return;
		}
		if (!pScript.endsWith(".java"))
			pScript = pScript + ".java";
		if (!EFIdraROMFormatLoader.parsers.containsKey(pScript)) {
				try {
					EFIdraROMFormatLoader.addUserScript(pScript);
					// script is not a parser script
					if (!EFIdraROMFormatLoader.parsers.containsKey(pScript)) {
						parser = null;
						return;
					}
				} catch (GhidraScriptLoadException | IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
//					JPanel panel = new JPanel(new BorderLayout());
//					Msg.showError(e, panel, "Error Loading ROM Parser", "Error loading " + pScript);
				}
		}
		parser = EFIdraROMFormatLoader.parsers.get(pScript);
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		EFIdraROMFormatLoader.init(program, monitor);
		guids = new EFIGUIDs();
		programBase = program.getImageBase();
		Listing listing = program.getListing();
		ProgramModule rootModule = listing.getDefaultRootModule();
		
		// probably try to give options to select the parser, along with an "all" option
		// "all" tries everything until one works without error?
		
		if (parser != null) {
			parser.parseROM(program, monitor);
		} else {
			for (EFIdraParserScript s : EFIdraROMFormatLoader.parsers.values()) {
				if (s.canParse(program)) {
					s.parseROM(program, monitor);
					parser = s;
					break;
				}
			}
		}
		if (parser != null) {
			analyzeExecutablesRecursive(rootModule, program, monitor, log);
		} else {
			JPanel panel = new JPanel(new BorderLayout());
			Msg.showError(this, panel, "No Parser Found", 
					"None of the available parsers were able to parse this ROM.");
		}
		
		return true;
	}
	
	public void analyzeExecutablesRecursive(ProgramModule module, Program program, 
			TaskMonitor monitor, MessageLog log) 
			throws CancelledException {
//		PortableExecutableAnalyzer peAnalyzer = new PortableExecutableAnalyzer();
//		FunctionStartPreFuncAnalyzer funcPreAnalyzer = new FunctionStartPreFuncAnalyzer();
//		FunctionStartPostAnalyzer funcPostAnalyzer = new FunctionStartPostAnalyzer();
//		EntryPointAnalyzer entryAnalyzer = new EntryPointAnalyzer();
//		Disassembler disassembler = Disassembler.getDisassembler(program, monitor, DisassemblerMessageListener.CONSOLE);
		monitor.setMessage("Analyzing Executables");
		Memory memory = program.getMemory();
		Listing listing = program.getListing();
		Namespace globalNamespace = program.getGlobalNamespace();
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
//						long baseOffs = exeBase.getOffset();
//						MemoryBlock progBlock = memory.createInitializedBlock(exeName, 
////								program.getImageBase(),
//								exeBase,
//								provider.getInputStream(0),
//								fragment.getMaxAddress().getOffset() - baseOffs, 
//								monitor, true);
						
						// create a new Namespace for this executable, to store all functions
						Namespace exeSpace = NamespaceUtils.createNamespaceHierarchy(exeName.replace(' ', '-'), 
								globalNamespace, program, SourceType.ANALYSIS);
						
						EFIdraExecutableData eData = new EFIdraExecutableData(exeName, 
								exeBase, exeSpace, progRoot, provider, program);
						
						// allow users to define/choose analyzers too
						for (EFIdraExecutableAnalyzerScript s : EFIdraROMFormatLoader.execAnalyzers) {
							if (s.canAnalyze(provider))
								s.initAndAnalyze(eData, log, monitor);
						}
						
						
//						ExecutableSectionAnalyzers.runPEAnalyzer(program, progRoot, 
//								disassembler, provider, exeName, exeBase, exeSpace, 
//								log, monitor);
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
					} catch (InvalidInputException e) {
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
