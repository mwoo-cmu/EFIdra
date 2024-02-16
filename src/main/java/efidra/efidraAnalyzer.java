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
import java.io.IOException;
import java.util.Arrays;

import javax.swing.JPanel;

import com.opencsv.exceptions.CsvValidationException;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StructureDataType;
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
	private static final DataType WORD = WordDataType.dataType;
	private static final DataType DWORD = DWordDataType.dataType;
	private static final DataType QWORD = QWordDataType.dataType;
	
	private StructureDataType GUID_STRUCT;
	private StructureDataType BLOCK_MAP_ENTRY_STRUCT;
	private StructureDataType VOLUME_HEADER_STRUCT;
	private StructureDataType EFI_FFS_INTEGRITY_CHECK;
	private StructureDataType FILE_HEADER_STRUCT;
	private StructureDataType FILE_HEADER2_STRUCT;
	
	public static final String LABEL_EFI_GUID = "EFI_GUID";
	public static final String LABEL_EFI_FV_BLOCK_MAP_ENTRY = "EFI_FV_BLOCK_MAP_ENTRY";
	public static final String LABEL_EFI_FIRMWARE_VOLUME_HEADER = "EFI_FIRMWARE_VOLUME_HEADER";
	public static final String LABEL_EFI_FFS_INTEGRITY_CHECK = "EFI_FFS_INTEGRITY_CHECK";
	public static final String LABEL_EFI_FFS_FILE_HEADER = "EFI_FFS_FILE_HEADER";
	public static final String LABEL_EFI_FFS_FILE_HEADER2 = "EFI_FFS_FILE_HEADER2";

	public efidraAnalyzer() {

		// TODO: Name the analyzer and give it a description.

		super("EFIdra UEFI Analyzer", "Analyze a loaded UEFI ROM", AnalyzerType.BYTE_ANALYZER);
		
		GUID_STRUCT = new StructureDataType(LABEL_EFI_GUID, 0);
		GUID_STRUCT.add(DWORD, "Data1", null);
		GUID_STRUCT.add(WORD, "Data2", null);
		GUID_STRUCT.add(WORD, "Data3", null);
		GUID_STRUCT.add(new ArrayDataType(BYTE, EFIGUIDs.EFI_GUID_DATA4_LEN, 
				BYTE.getLength()), "Data4", null);
		
		BLOCK_MAP_ENTRY_STRUCT = new StructureDataType(LABEL_EFI_FV_BLOCK_MAP_ENTRY, 0);
		BLOCK_MAP_ENTRY_STRUCT.add(DWORD, "NumBlocks", 
				"The number of sequential blocks which are of the same size.");
		BLOCK_MAP_ENTRY_STRUCT.add(DWORD, "Length",
				"The size of the blocks.");
		
		VOLUME_HEADER_STRUCT = new StructureDataType(LABEL_EFI_FIRMWARE_VOLUME_HEADER, 0);
		VOLUME_HEADER_STRUCT.add(new ArrayDataType(BYTE, EFIFirmwareVolume.ZERO_VECTOR_LEN, 
				BYTE.getLength()), "ZeroVector", 
				"The first 16 bytes are reserved to allow for the reset vector of\n"
						+ "	processors whose reset vector is at address 0.");
		VOLUME_HEADER_STRUCT.add(GUID_STRUCT, "FileSystemGuid", 
				"Declares the file system with which the firmware volume is formatted.");
		VOLUME_HEADER_STRUCT.add(QWORD, "FvLength", 
				"Length in bytes of the complete firmware volume, including the header.");
		VOLUME_HEADER_STRUCT.add(StringDataType.dataType, 4, "Signature",
				"Set to EFI_FVH_SIGNATURE");
		VOLUME_HEADER_STRUCT.add(DWORD, "Attributes",
				"Declares capabilities and power-on defaults for the firmware volume.");
		VOLUME_HEADER_STRUCT.add(WORD, "HeaderLength",
				"Length in bytes of the complete firmware volume header.");
		VOLUME_HEADER_STRUCT.add(WORD, "Checksum",
				"A 16-bit checksum of the firmware volume header. A valid header sums to zero.");
		VOLUME_HEADER_STRUCT.add(WORD, "ExtHeaderOffset", 
				"Offset, relative to the start of the header, of the extended header\n"
				+ "(EFI_FIRMWARE_VOLUME_EXT_HEADER) or zero if there is no extended header.");
		VOLUME_HEADER_STRUCT.add(BYTE, "Reserved",
				"This field must always be set to zero.");
		VOLUME_HEADER_STRUCT.add(WORD, "Revision",
				"Set to 2. Future versions of this specification may define new header fields and will\n"
				+ "increment the Revision field accordingly.");
		VOLUME_HEADER_STRUCT.add(BLOCK_MAP_ENTRY_STRUCT, "BlockMap",
				"An array of run-length encoded FvBlockMapEntry structures. The array is\n"
				+ "terminated with an entry of {0,0}.");
		
		EFI_FFS_INTEGRITY_CHECK = new StructureDataType(LABEL_EFI_FFS_INTEGRITY_CHECK, 0);
		EFI_FFS_INTEGRITY_CHECK.add(BYTE, "Header", "8-bit checksum of the file header");
		EFI_FFS_INTEGRITY_CHECK.add(BYTE, "File", "8-bit checksum of the file contents");
		
		FILE_HEADER_STRUCT = new StructureDataType(LABEL_EFI_FFS_FILE_HEADER, 0);
		FILE_HEADER_STRUCT.add(GUID_STRUCT, "Name", 
				"This GUID is the file name. It is used to uniquely identify the file.");
		FILE_HEADER_STRUCT.add(EFI_FFS_INTEGRITY_CHECK, "IntegrityCheck", 
				"Used to verify the integrity of the file.");
		FILE_HEADER_STRUCT.add(BYTE, "Type", "Identifies the type of file.");
		FILE_HEADER_STRUCT.add(BYTE, "Attributes", "Declares various file attribute bits.");
		FILE_HEADER_STRUCT.add(new ArrayDataType(BYTE, EFIFirmwareFile.EFI_FF_SIZE_LEN, 
				BYTE.getLength()), "Size", 
				"The length of the file in bytes, including the FFS header.");
		FILE_HEADER_STRUCT.add(BYTE, "State", 
				"Used to track the state of the file throughout the life of the file from creation to deletion.");
		
//		FILE_HEADER2_STRUCT = FILE_HEADER_STRUCT.clone();
		FILE_HEADER2_STRUCT = new StructureDataType(LABEL_EFI_FFS_FILE_HEADER2, 0);
		FILE_HEADER2_STRUCT.add(GUID_STRUCT, "Name", 
				"This GUID is the file name. It is used to uniquely identify the file.");
		FILE_HEADER2_STRUCT.add(EFI_FFS_INTEGRITY_CHECK, "IntegrityCheck", 
				"Used to verify the integrity of the file.");
		FILE_HEADER2_STRUCT.add(BYTE, "Type", "Identifies the type of file.");
		FILE_HEADER2_STRUCT.add(BYTE, "Attributes", "Declares various file attribute bits.");
		FILE_HEADER2_STRUCT.add(new ArrayDataType(BYTE, EFIFirmwareFile.EFI_FF_SIZE_LEN, 
				BYTE.getLength()), "Size", 
				"The length of the file in bytes, including the FFS header.");
		FILE_HEADER2_STRUCT.add(BYTE, "State", 
				"Used to track the state of the file throughout the life of the file from creation to deletion.");
		FILE_HEADER2_STRUCT.add(QWORD, "ExtendedSize", 
				"If FFS_ATTRIB_LARGE_FILE is set in Attributes, then ExtendedSize exists and Size must be set to zero.\n"
				+ "If FFS_ATTRIB_LARGE_FILE is not set then EFI_FFS_FILE_HEADER is used.");
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

	private void addStructuresRecursive(ProgramModule module, Listing listing) {
		for (Group programItem : module.getChildren()) {
			if (programItem instanceof ProgramFragment) {
				ProgramFragment programFragment = (ProgramFragment) programItem;
				if (programFragment.getName().contains("UEFI Volume Header")) {
					// this is a header fragment
					try {
						Address vhBase = programFragment.getMinAddress();
						String checksum = listing.getComment(CodeUnit.PRE_COMMENT, vhBase);
						listing.createData(vhBase, VOLUME_HEADER_STRUCT);
						listing.setComment(vhBase.add(EFIFirmwareVolume.EFI_FV_CHECKSUM_OFFSET), 
								CodeUnit.PRE_COMMENT, checksum);
					} catch (CodeUnitInsertionException e) {
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
						if (LABEL_EFI_FFS_FILE_HEADER2.equals(comment)) {
							listing.createData(fhBase, FILE_HEADER2_STRUCT);
							programFragment.setComment("");
						} else if (LABEL_EFI_FFS_FILE_HEADER.equals(comment)) {
							listing.createData(fhBase, FILE_HEADER_STRUCT);
							programFragment.setComment("");
						}
						listing.setComment(fhBase.add(EFIFirmwareFile.EFI_FF_CHECKSUM_OFFSET), 
								CodeUnit.PRE_COMMENT, checksum);
					} catch (CodeUnitInsertionException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			} else if (programItem instanceof ProgramModule) {
				ProgramModule programModule = (ProgramModule) programItem;
				addStructuresRecursive(programModule, listing);
			}
		}
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// TODO: Perform analysis when things get added to the 'program'.  Return true if the
		// analysis succeeded.
		
		Listing listing = program.getListing();
		ProgramModule rootModule = listing.getDefaultRootModule();
		
		// create data objects for the headers of files and volumes
		addStructuresRecursive(rootModule, listing);
		
		
		return false;
	}
}
