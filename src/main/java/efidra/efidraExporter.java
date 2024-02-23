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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import ghidra.app.util.*;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Group;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this exporter does.
 */
public class efidraExporter extends Exporter {

	public static final List<Byte> PE_SECTION_TYPES = Arrays.asList(new Byte[] {
			EFIFirmwareSection.EFI_SECTION_PE32,
			EFIFirmwareSection.EFI_SECTION_TE
	});
	
//	private static Address programBase;
	
	/**
	 * Exporter constructor.
	 */
	public efidraExporter() {

		// TODO: Name the exporter and associate a file extension with it

		super("EFIdra Zip Executable Exporter", "zip", null);
	}

	@Override
	public boolean supportsAddressRestrictedExport() {

		// TODO: return true if addrSet export parameter can be used to restrict export

		// in this case, we will export all PEIM files from the ROM, so no 
		// address set selection should be used. Another exporter may be defined to 
		// export a specific file.
		return false;
	}

	private static void addFilesByTypeRecursive(ProgramModule module, List<Byte> fileType, Memory memory, 
			Listing listing, ZipOutputStream zipOs, File outputDir) throws IllegalArgumentException {
		if (zipOs == null && outputDir == null)
			throw new IllegalArgumentException("No output specified.");
		for (Group programItem : module.getChildren()) {
			if (programItem instanceof ProgramFragment && !programItem.getName().startsWith("UEFI Volume Header")) {
				try {
					ProgramFragment programFragment = (ProgramFragment) programItem;
					EFIFirmwareFile efiFile = new EFIFirmwareFile(memory, programFragment);
					for (EFIFirmwareSection section : efiFile.getSections()) {
						if (fileType.contains(section.getType())) {
							StringBuilder sb = new StringBuilder();
							for (String parent : programItem.getParentNames()) {
								// pull the name/GUID without the unique address
								sb.append(parent.split(Pattern.quote(" (0x"))[0] + "/");
							}
							if (outputDir != null) {
								File dir = new File(outputDir, sb.toString());
								dir.mkdirs();
							}
							sb.append(programItem.getName().split(Pattern.quote(" (0x"))[0]);
							if (section.getType() == EFIFirmwareSection.EFI_SECTION_PE32) {
								sb.append("_PE32_Section");
							} else if (section.getType() == EFIFirmwareSection.EFI_SECTION_TE) {
								sb.append("_TE_Section");
							}
							sb.append(".efi");
							Msg.info(null, sb.toString());
//							Address sectionBase = programBase.add(section.getBasePointer());
							// again, here we assume that the program fragment 
							// representing a valid EFI Firmware File is the first 
							// address range in its program fragment
//							byte[] sectionBytes = new byte[section.getSize()];
							byte[] sectionBytes = section.getSectionData();
//							memory.getBytes(sectionBase, sectionBytes);
							if (zipOs != null) {
								ZipEntry entry = new ZipEntry(sb.toString());
								zipOs.putNextEntry(entry);
								zipOs.write(sectionBytes);
								zipOs.closeEntry();
							}
							if (outputDir != null) {
								File outf = new File(outputDir, sb.toString());
								FileOutputStream fOs = new FileOutputStream(outf);
								fOs.write(sectionBytes);
								fOs.close();
							}
						}
					}
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} else if (programItem instanceof ProgramModule) {
				addFilesByTypeRecursive((ProgramModule) programItem, fileType, memory, listing, zipOs, outputDir);
			}
		}
	}
	
	private static void addFilesByTypeRecursive(ProgramModule module, List<Byte> fileType, Memory memory, 
			Listing listing, ZipOutputStream zipOs) {
		addFilesByTypeRecursive(module, fileType, memory, listing, zipOs, null);
	}
	
	public static void addFilesByTypeRecursive(ProgramModule module, List<Byte> fileType, Memory memory, 
			Listing listing, File outputDir) {
		addFilesByTypeRecursive(module, fileType, memory, listing, null, outputDir);
	}
	
	@Override
	public boolean export(File file, DomainObject domainObj, AddressSetView addrSet,
			TaskMonitor monitor) throws ExporterException, IOException {

		// TODO: Perform the export, and return true if it succeeded
		// check if the DomainObject is a ProgramDB or even if it implements Program
		if (!(domainObj instanceof Program)) {
			// if so, we can access Memory and Listing, and continue from there
			// otherwise return false;
			return false;
		}
		// the addrSet will be null if no section is highlighted when export is selected
		
		Program program = (Program) domainObj;
//		programBase = program.getImageBase();
		Memory memory = program.getMemory();
		Listing listing = program.getListing();
		ProgramModule rootModule = listing.getDefaultRootModule();
		
		// attempt to create the file if it doesn't exist		
		file.createNewFile();
		FileOutputStream fileOs = new FileOutputStream(file);
		ZipOutputStream zipOs = new ZipOutputStream(fileOs);
		
		addFilesByTypeRecursive(rootModule, PE_SECTION_TYPES, memory, listing, zipOs);
		
		zipOs.close();
		fileOs.close();
		return true;
	}

	@Override
	public List<Option> getOptions(DomainObjectService domainObjectService) {
		List<Option> list = new ArrayList<>();

		// TODO: If this exporter has custom options, add them to 'list'
//		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public void setOptions(List<Option> options) throws OptionException {

		// TODO: If this exporter has custom options, assign their values to the exporter here
	}
}
