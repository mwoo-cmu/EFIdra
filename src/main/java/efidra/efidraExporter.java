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
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import ghidra.app.util.*;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Group;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this exporter does.
 */
public class efidraExporter extends Exporter {

	/**
	 * Exporter constructor.
	 */
	public efidraExporter() {

		// TODO: Name the exporter and associate a file extension with it

		super("EFIdra Executable Exporter", "zip", null);
	}

	@Override
	public boolean supportsAddressRestrictedExport() {

		// TODO: return true if addrSet export parameter can be used to restrict export

		// in this case, we will export all PEIM files from the ROM, so no 
		// address set selection should be used. Another exporter may be defined to 
		// export a specific file.
		return false;
	}

	private void addFilesByTypeRecursive(ProgramModule module, List<Byte> fileType, Memory memory, 
			Listing listing, ZipOutputStream zipOs) {
		for (Group programItem : module.getChildren()) {
			if (programItem instanceof ProgramFragment) {
				try {
					ProgramFragment programFragment = (ProgramFragment) programItem;
					EFIFirmwareFile efiFile = new EFIFirmwareFile(memory, programFragment);
					if (fileType.contains(efiFile.getType())) {
						StringBuilder sb = new StringBuilder();
						for (String parent : programItem.getParentNames()) {
							// pull the name/GUID without the unique address
							sb.append(parent.split(" (0x")[0] + "/");
						}
						sb.append(programItem.getName().split(" (0x")[0] + ".efi");
						Address fileBase = programFragment.getMinAddress();
						// again, here we assume that the program fragment 
						// representing a valid EFI Firmware File is the first 
						// address range in its program fragment
						byte[] fileBytes = new byte[(int) programFragment.getFirstRange().getLength()];
						memory.getBytes(fileBase, fileBytes);
						ZipEntry entry = new ZipEntry(sb.toString());
						zipOs.putNextEntry(entry);
						zipOs.write(fileBytes);
						zipOs.closeEntry();
					}
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (MemoryAccessException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			} else if (programItem instanceof ProgramModule) {
				addFilesByTypeRecursive((ProgramModule) programItem, fileType, memory, listing, zipOs);
			}
		}
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
		Memory memory = program.getMemory();
		Listing listing = program.getListing();
		ProgramModule rootModule = listing.getDefaultRootModule();
		
		// attempt to create the file if it doesn't exist		
		file.createNewFile();
		FileOutputStream fileOs = new FileOutputStream(file);
		ZipOutputStream zipOs = new ZipOutputStream(fileOs);
		
		List<Byte> PE_types = Arrays.asList(new Byte[] {
				EFIFirmwareFile.EFI_FV_FILETYPE_PEI_CORE,
				EFIFirmwareFile.EFI_FV_FILETYPE_PEIM,
				EFIFirmwareFile.EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER,
		});
		
		addFilesByTypeRecursive(rootModule, PE_types, memory, listing, zipOs);
		
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
