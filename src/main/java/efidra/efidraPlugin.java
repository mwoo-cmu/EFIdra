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
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import javax.swing.*;

import com.opencsv.exceptions.CsvValidationException;

import docking.ActionContext;
import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.mem.Memory;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.app.script.AskDialog;
import resources.Icons;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = EfidraPluginPackage.NAME,
	category = PluginCategoryNames.MISC,
	shortDescription = "Plugin suite for analyzing UEFI ROMs",
	description = "Plugin long description goes here."
)
//@formatter:on
public class efidraPlugin extends Plugin {

//	EFIdraProvider provider;
	
	EFIGUIDs guids;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public efidraPlugin(PluginTool tool) {
		super(tool);

		// TODO: Customize provider (or remove if a provider is not desired)
//		String pluginName = getName();
//		provider = new EFIdraProvider(this, pluginName);
		guids = new EFIGUIDs(); 
//		buildPanel();
		createActions();

		// TODO: Customize help (or remove if help is not desired)
//		String topicName = this.getClass().getPackage().getName();
//		String anchorName = "HelpAnchor";
//		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}
	
	// Customize GUI
	private void buildPanel() {
//		panel = new JPanel(new BorderLayout());
	}

	private void createActions() {
		new ActionBuilder("Load GUIDs URL", getName())
			.menuPath("&EFIdra", "GUID Database", "Load From URL")
			.menuIcon(null)
			.onAction(c -> {
				AskDialog urlDialog = new AskDialog("Load GUID Database", "URL", AskDialog.STRING, "");
				String URL = urlDialog.getTextFieldValue();
//				String URL = askString("Load GUID Database", "URL");
				JPanel panel = new JPanel(new BorderLayout());
				try {
					guids.parseGUIDsFromURL(URL);
				} catch (CsvValidationException | IOException e) {
					Msg.showError(e, panel, "EFIdra GUIDs", "Error loading GUIDs from " + URL);
					e.printStackTrace();
					return;
				}
				Msg.showInfo(getClass(), panel, "EFIdra GUIDs", "GUIDs loaded successfuly.");
				
			})
			.enabled(true)
			.description("Load a GUID database from a URL link")
			.buildAndInstall(tool);
		new ActionBuilder("Load GUIDs File", getName())
			.menuPath("&EFIdra", "GUID Database", "Load From File")
			.menuIcon(null)
			.onAction(c -> {
				GhidraFileChooser fileChooser = new GhidraFileChooser(null);
				File file = fileChooser.getSelectedFile();
				JPanel panel = new JPanel(new BorderLayout());
				try {
					guids.parseGUIDsFromFile(file);
				} catch (CsvValidationException | IOException e) {
					Msg.showError(e, panel, "EFIdra GUIDs", "Error loading GUIDs from " + file.toString());
					e.printStackTrace();
					return;
				}
				Msg.showInfo(fileChooser, panel, "EFIdra GUIDs", file.toString());
			})
			.enabled(true)
			.description("Load a GUID database from a CSV file")
			.buildAndInstall(tool);
		new ActionBuilder("Clear GUID Databse", getName())
			.menuPath("&EFIdra", "GUID Database", "Empty Database")
			.menuIcon(null)
			.onAction(c -> {
				guids.clearGUIDs();
				JPanel panel = new JPanel(new BorderLayout());
				Msg.showError(null, panel, "EFIdra GUIDs", "Database cleared");
			})
			.enabled(true)
			.description("Clear the GUID to readable name mappings")
			.buildAndInstall(tool);
		new ActionBuilder("Convert GUID", getName())
			.menuPath("&EFIdra", "GUID Database", "Convert GUID")
			.menuIcon(null)
			.onAction(c -> {
				AskDialog guidDialog = new AskDialog("Find GUID Readable Name", "GUID", AskDialog.STRING, "");
				String guid = guidDialog.getTextFieldValue().toUpperCase();
				JPanel panel = new JPanel(new BorderLayout());
				String readableName = guids.getReadableName(guid);
				if (readableName.equals(guid)) {
					Msg.showInfo(getClass(), panel, "EFIdra GUIDs", "Couldn't find a readable name for " + guid);
				} else {
					Msg.showInfo(getClass(), panel, "EFIdra GUIDs", readableName + " (" + guid + ")");
				}
			})
			.enabled(true)
			.description("Convert a GUID to its readable name, if available")
			.buildAndInstall(tool);
		// non-zip export of executables
		new ActionBuilder("Export Executables to Directory", getName())
			.menuPath("&EFIdra", "Export Executables to Directory")
			.menuIcon(null)
			.onAction(c -> {
				GhidraFileChooser fileChooser = new GhidraFileChooser(null);
				fileChooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
				File file = fileChooser.getSelectedFile();
				JPanel panel = new JPanel(new BorderLayout());
				// when run in the Code Browser, c should be a 
				// ProgramActionContext, so we can get the relevant program data.
				if (!(c instanceof ProgramActionContext)) {
					Msg.showError(null, panel, "Export Executables to Directory", 
							"Error exporting executables: Current Context is not a Program Context");
					return;
				}
				ProgramActionContext programContext = (ProgramActionContext) c;
				Program program = programContext.getProgram();
				Memory memory = program.getMemory();
				Listing listing = program.getListing();
				ProgramModule rootModule = listing.getDefaultRootModule();
				efidraExporter.addFilesByTypeRecursive(rootModule, efidraExporter.PE_SECTION_TYPES, memory, listing, file);
			})
			.enabled(true)
			.description("Export all executables in this ROM to a given Directory")
			.buildAndInstall(tool);
	}
	
	@Override
	public void init() {
		super.init();

		// TODO: Acquire services if necessary
	}

////// TODO: If provider is desired, it is recommended to move it to its own file
//private static class EFIdraProvider extends ComponentProvider {
//
//	private JPanel panel;
//	private DockingAction action;
//
//	public EFIdraProvider(Plugin plugin, String owner) {
//		super(plugin.getTool(), owner, owner);
//		buildPanel();
////		action = new DockingAction("My Action", getName()) {
////			@Override
////			public void actionPerformed(ActionContext context) {
////				Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
////			}
////		};
////		action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
////		action.setEnabled(true);
////		action.markHelpUnnecessary();
////		dockingTool.addLocalAction(this, action);
//		createActions();
//	}
//
//	// Customize GUI
//	private void buildPanel() {
//		panel = new JPanel(new BorderLayout());
////		JTextArea textArea = new JTextArea(5, 25);
////		textArea.setEditable(false);
////		panel.add(new JScrollPane(textArea));
//		setVisible(true);
//	}
//
//	// TODO: Customize actions
//	private void createActions() {
//		action = new ActionBuilder("Load GUID Database", getName())
//				.description("Load a GUID database to map labels from")
////				.menuPath("&efidraPlugin", "Load GUID database")
//				.menuPath(ToolConstants.MENU_TOOLS, "Load GUID database")
//				.menuIcon(null)
//				.onAction(c -> {
//					Msg.showInfo(getClass(), panel, "Test", "EFIGuid Action");
//				})
//				.enabled(true)
//				
//				.buildAndInstall(dockingTool);
//	}
//
//	@Override
//	public JComponent getComponent() {
//		return panel;
//	}
//}
}
