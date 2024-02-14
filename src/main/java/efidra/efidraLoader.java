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
import java.util.*;

import javax.swing.JPanel;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.CompilerSpecDescription;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class efidraLoader extends AbstractProgramWrapperLoader {

	// "_FVH" stored little endian
	private static final int EFI_FVH_SIGNATURE = 0x4856465f;
	private List<EFIFirmwareVolume> volumes;
	private long paddingOffset;
	
	@Override
	public String getName() {

		// TODO: Name the loader.  This name must match the name of the loader in the .opinion 
		// files.

		return "UEFI ROM (EFIdra)";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// Examine the bytes in 'provider' to determine if this loader can load it.
		// a lot of other loaders don't seem to do any check here...
//		findFirmwareVolumes(provider);
//		JPanel panel = new JPanel(new BorderLayout());
//		Msg.showInfo(getClass(), panel, "EFIdra Loader", "Volumes Found: " + volumes.size());
//		if (volumes.size() > 0) {
			// load language/compiler pairs for the processor supported by UEFI
			// should we create a processor type for Itanium as well?
		for (String processor : new String[] {"x86", "AARCH64"}) {
			List<LanguageDescription> langDescs = 
					getLanguageService().getLanguageDescriptions(Processor.toProcessor(processor));
			for (LanguageDescription langDesc : langDescs) {
				// UEFI only supports little endian
				if (langDesc.getEndian().isBigEndian())
					continue;
				if (langDesc.getSize() == 16) {
					continue;
				}
				Collection<CompilerSpecDescription> compDescs = 
						langDesc.getCompatibleCompilerSpecDescriptions();
				for (CompilerSpecDescription compDesc : compDescs) {
					loadSpecs.add(new LoadSpec(this, 0, 
							new LanguageCompilerSpecPair(langDesc.getLanguageID(), 
									compDesc.getCompilerSpecID()), false));
				}
			}
//			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair()))
		}
//		}
		
		return loadSpecs;
	}

	private void findFirmwareVolumes(ByteProvider provider) throws IOException {
		// all UEFI images are little endian
		BinaryReader reader = new BinaryReader(provider, true);
		// do I need to set ptr index?
//		reader.setPointerIndex(0);
		long fileLen = provider.length();
		long curIdx = 0;
		volumes = new ArrayList<>();
		paddingOffset = 0;
		while (curIdx < fileLen) {
			int next = reader.readNextInt();
			if (paddingOffset == 0 && next != 0) {
				// find the start of the ROM excluding all the padding at the beginning
				// need to offset by the int read and the size of the zero vector
				paddingOffset = reader.getPointerIndex() - BinaryReader.SIZEOF_INT - EFIFirmwareVolume.ZERO_VECTOR_LEN;
			}
			if (next == EFI_FVH_SIGNATURE) {
				reader.setPointerIndex(reader.getPointerIndex() - BinaryReader.SIZEOF_INT - EFIFirmwareVolume.EFI_SIG_OFFSET);
				// after this call, reader will be pointed at the end of the 
				// last firmware volume, so next header will be the next fv
				volumes.add(new EFIFirmwareVolume(reader));
			}
			curIdx = reader.getPointerIndex();
		}
//		return volumes;
	}
	
	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		Address progBase = program.getImageBase();
		findFirmwareVolumes(provider);
		Memory memory = program.getMemory();
		
		Listing listing = program.getListing();
		ProgramModule rootModule = listing.getDefaultRootModule();
		try {
			memory.createInitializedBlock("Unpadded Full ROM", progBase.add(paddingOffset), 
					provider.getInputStream(paddingOffset), provider.length() - paddingOffset,
					monitor, false);
		} catch (LockException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (MemoryConflictException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (AddressOverflowException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CancelledException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// label all of the volumes we've found
		EFIGUIDs guids = new EFIGUIDs();
		for (EFIFirmwareVolume volume : volumes) {
			try {
				ProgramModule volumeModule = rootModule.createModule(
						guids.getReadableName(
								volume.getNameGUID()) + " (0x" + Long.toHexString(volume.getBasePointer()) + ")");
				ProgramFragment headerFrag = volumeModule.createFragment(
						"UEFI Volume Header (0x" + Long.toHexString(volume.getBasePointer()) + ")");
				try {
					Address headerBase = progBase.add(volume.getBasePointer()); 
					headerFrag.move(headerBase, headerBase.add(volume.getHeaderLength()));
				} catch (NotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (AddressOutOfBoundsException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				for (EFIFirmwareFile file : volume.getFiles()) {
					try {
						String fileGUIDName = guids.getReadableName(file.getNameGUID());
						ProgramFragment fileFrag = volumeModule.createFragment(
								fileGUIDName + " (0x" + Long.toHexString(volume.getBasePointer()) + ")");
						Address fileBase = progBase.add(file.getBasePointer()); 
						fileFrag.move(fileBase, fileBase.add(file.getSize()));
					} catch (NotFoundException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			} catch (DuplicateNameException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
//		list.add(new Option("Convert GUIDs to Names", true));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
