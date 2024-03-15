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

import javax.swing.JPanel;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import generic.jar.ResourceFile;
import ghidra.app.analyzers.PortableExecutableAnalyzer;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptLoadException;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.JavaScriptProvider;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
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
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class efidraAnalyzer extends AbstractAnalyzer {
	private static final DataType BYTE = ByteDataType.dataType;
	private static final DataType USHORT = UnsignedShortDataType.dataType;
	private static final DataType UINT = UnsignedIntegerDataType.dataType;
	private static final DataType ULONG = UnsignedLongDataType.dataType;
	private static final DataType WORD = WordDataType.dataType;
	private static final DataType DWORD = DWordDataType.dataType;
	private static final DataType QWORD = QWordDataType.dataType;
	
//	private StructureDataType GUID_STRUCT;
//	private StructureDataType BLOCK_MAP_ENTRY_STRUCT;
//	private StructureDataType VOLUME_HEADER_STRUCT;
//	private StructureDataType EFI_FFS_INTEGRITY_CHECK;
//	private StructureDataType FILE_HEADER_STRUCT;
//	private StructureDataType FILE_HEADER2_STRUCT;
//	private StructureDataType SECTION_HEADER_STRUCT;
//	private StructureDataType SECTION_HEADER2_STRUCT;
	
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

	private void applyFileOrVolumeHeader(ProgramFragment programFragment, Listing listing, Memory memory) {
		if (programFragment.getName().startsWith("UEFI Volume Header")) {
			// this is a header fragment
			try {
				Address vhBase = programFragment.getMinAddress();
				String checksum = listing.getComment(CodeUnit.PRE_COMMENT, vhBase);
				listing.createData(vhBase, EFIdraROMFormatLoader.getType("EFI_FIRMWARE_VOLUME_HEADER"));
//				listing.createData(vhBase, VOLUME_HEADER_STRUCT);
				StringBuilder volHeaderSb = new StringBuilder();
				EFIFirmwareVolume fragVolHeader = new EFIFirmwareVolume(memory, programFragment);
				String fvGUID = fragVolHeader.getNameGUID();
				String fvName = guids.getReadableName(fvGUID);
				volHeaderSb.append(fvName);
				if (!fvName.equals(fvGUID)) {
					volHeaderSb.append(" (" +fvGUID + ")");
				}
				volHeaderSb.append("\n" + checksum);
				listing.setComment(vhBase, 
						CodeUnit.PRE_COMMENT, volHeaderSb.toString());
			} catch (CodeUnitInsertionException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} else {
			// non-header fragment should be a file 
			// (we should set up something for non-uefi files and padding space, though)
			try {
				Address fhBase = programFragment.getMinAddress();
				String checksum = listing.getComment(CodeUnit.PRE_COMMENT, fhBase);
				String comment = programFragment.getComment();
				if (LABEL_EFI_FFS_FILE_HEADER.equals(comment)) {
					listing.createData(fhBase, EFIdraROMFormatLoader.getType("EFI_FFS_FILE_HEADER"));
					programFragment.setComment("");
				} else if (LABEL_EFI_FFS_FILE_HEADER2.equals(comment)) {
					listing.createData(fhBase, EFIdraROMFormatLoader.getType("EFI_FFS_FILE_HEADER2"));
					programFragment.setComment("");
				} else {
					return;
				}
				StringBuilder fileHeaderSb = new StringBuilder();
				EFIFirmwareFile fragFile = new EFIFirmwareFile(memory, programFragment);
				String ffGUID = fragFile.getNameGUID();
				String ffName = guids.getReadableName(ffGUID);
				fileHeaderSb.append(ffName);
				if (!ffName.equals(ffGUID)) {
					fileHeaderSb.append(" (" + ffGUID + ")");
				}
				fileHeaderSb.append("\n" + checksum);
				listing.setComment(fhBase, 
						CodeUnit.PRE_COMMENT, fileHeaderSb.toString());
				for (EFIFirmwareSection fragSec : fragFile.getSections()) {
					listing.createData(programBase.add(fragSec.getBasePointer()), 
							fragSec.getHeaderSize() == EFIFirmwareSection.EFI_SECTION_HEADER_SIZE ? 
									EFIdraROMFormatLoader.getType("EFI_COMMON_SECTION_HEADER") : 
										EFIdraROMFormatLoader.getType("EFI_COMMON_SECTION_HEADER2"));
				}
			} catch (CodeUnitInsertionException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
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
	
	private void addStructuresRecursive(ProgramModule module, Listing listing, Memory memory) {
		for (Group programItem : module.getChildren()) {
			if (programItem instanceof ProgramFragment) {
				ProgramFragment programFragment = (ProgramFragment) programItem;
//				MemoryBlock fragBlock = memory.getBlock(programFragment.getMinAddress());
				applyFileOrVolumeHeader(programFragment, listing, memory);
				if (programFragment.getName().startsWith("NVRAM") || 
						programFragment.getName().startsWith(NVRAM_GUID)) {
					try {
						parseNVRAMStructures(programFragment, listing, memory);
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (CodeUnitInsertionException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			} else if (programItem instanceof ProgramModule) {
				ProgramModule programModule = (ProgramModule) programItem;
				addStructuresRecursive(programModule, listing, memory);
			}
		}
	}
	
	private void initStructures(Program program) {
		EFIdraROMFormatLoader.init(program);
	}
	
//	private void findFirmwareVolumes(ByteProvider provider) throws IOException {
//		// all UEFI images are little endian
//		BinaryReader reader = new BinaryReader(provider, true);
//		long fileLen = provider.length();
//		long curIdx = 0;
//		volumes = new ArrayList<>();
//		paddingOffset = 0;
//		while (curIdx < fileLen) {
//			int next = reader.readNextInt();
//			if (paddingOffset == 0 && next != 0) {
//				// find the start of the ROM excluding all the padding at the beginning
//				// need to offset by the int read and the size of the zero vector
//				paddingOffset = reader.getPointerIndex() - BinaryReader.SIZEOF_INT - EFIFirmwareVolume.ZERO_VECTOR_LEN;
//			}
//			if (next == EFIFirmwareVolume.EFI_FVH_SIGNATURE) {
//				reader.setPointerIndex(reader.getPointerIndex() - BinaryReader.SIZEOF_INT - EFIFirmwareVolume.EFI_SIG_OFFSET);
//				// after this call, reader will be pointed at the end of the 
//				// last firmware volume, so next header will be the next fv
//				volumes.add(new EFIFirmwareVolume(reader));
//			}
//			curIdx = reader.getPointerIndex();
//		}
//		// in case malformed volumes have read too far
//		reader.setPointerIndex(fileLen);
//	}
	
//	private GhidraScript get
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// TODO: Perform analysis when things get added to the 'program'.  Return true if the
		// analysis succeeded.
		
		initStructures(program);
		guids = new EFIGUIDs();
		programBase = program.getImageBase();
		Listing listing = program.getListing();
		ProgramModule rootModule = listing.getDefaultRootModule();
		Memory memory = program.getMemory();
		
		// create data objects for the headers of files and volumes
//		addStructuresRecursive(rootModule, listing, memory);
		
		// probably try to give options to select the parser, along with an "all" option
		// "all" tries everything until one works without error?
		
		ResourceFile scriptFile = GhidraScriptUtil.findScriptByName("PiFirmwareParser.java");
		if (scriptFile == null) {
			try {
				scriptFile = Application.getModuleDataFile(
						EFIdraROMFormatLoader.EFI_ROM_FORMATS_DIR + "/" + "PiFirmwareParser.java");
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		PrintWriter writer = new PrintWriter(System.out);
		try {
			GhidraScript script = GhidraScriptUtil.getProvider(scriptFile).getScriptInstance(scriptFile, writer);
			EFIdraParserScript eScript = (EFIdraParserScript) script;
			eScript.parseROM(program);
		} catch (GhidraScriptLoadException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		
		
		return true;
	}
	
	public void analyzeExecutables(Program program, TaskMonitor monitor, MessageLog log) 
			throws CancelledException {
		
		PortableExecutableAnalyzer a = new PortableExecutableAnalyzer();
		for (;;) {
			a.added(program, null, monitor, log);
		}
	}
}
