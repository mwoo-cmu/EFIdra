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

import javax.swing.*;

import com.opencsv.exceptions.CsvValidationException;

import docking.ActionContext;
import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
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
	
	EFIGUIDNames guids;

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
		guids = new EFIGUIDNames(); 
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
	}
	
	@Override
	public void init() {
		super.init();

		// TODO: Acquire services if necessary
	}


}
