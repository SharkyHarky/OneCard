package com.radiius;

import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JPanel;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileSystemView;

import com.helixion.globalplatform.GPConstants;
import com.helixion.globalplatform.GPLoader;
import com.helixion.globalplatform.GP_SCP;
import com.helixion.gui.FormPanel;
import com.helixion.lok.logger.LogLineType;
import com.helixion.lok.lokSimTester.scriptutils.TestScriptConstants;
import com.helixion.lok.scriptmanager.ScriptManager;
import com.helixion.lok.scripts.JavaScript;
import com.helixion.lok.scripts.ScriptResults;
import com.helixion.lok.scripts.ScriptRunStates;
import com.helixion.lok.scripts.ScriptTypes;
import com.helixion.lok.testcomponent.carddetails.CardDetails;
import com.helixion.lok.testcomponent.carddetails.CardDetailsTestComponent;
import com.helixion.lok.testcomponent.carddetails.configvmpa.VMPADetails;
import com.helixion.smartcardio.cardreader.CardInterface;
import com.helixion.smartcardio.cardreader.CardReaderTestComponent;

/**
 * This test has to trigger an CDI check in the PM.
 *
 * As it's the first one after personalisation and the IURO has been set to
 * trigger a interval based Issuer Update this should fire off an Issuer Update.
 *
 * @author Steve Harkins
 */
public class LoadPackage extends JavaScript implements TestScriptConstants, ActionListener {

    private final static String BROWSE = "Browse";
    private final static String SUBMIT = "Load";
    private final static String SELECT_CAP_FILE = "select Cap File";
    private JDialog formDialog;
    private FormPanel form;
    private String capFilePath;

    public LoadPackage(ScriptManager scriptmanager) {
        super(scriptmanager);
    }

    /* (non-Javadoc)
     * @see com.helixion.lok.scripts.Script#getName()
     */
    public String getName() {
        return "Load CAP file";
    }

    /* (non-Javadoc)
     * @see com.helixion.lok.scripts.Script#getPackage()
     */
    public String[] getPackageTree() {
        return new String[] {"Radiius"} ;
    }

    /* (non-Javadoc)
     * @see com.helixion.lok.scripts.Script#getDescription()
     */
    public String getDescription() {
        return "Loads the selected cap file." ;
    }

    /* (non-Javadoc)
     * @see com.helixion.lok.scripts.Script#getScriptType()
     */
    public ScriptTypes getScriptType() {
        return ScriptTypes.UTILITY;
    }

    public void run() {
         boolean isSuccess = false;
         capFilePath = null;

        // Do some things.
        // display panel to get cap file path
        form = new FormPanel();
        JPanel frmPanel = setConfigurationPanel(form);
        form.add(frmPanel);

        GridBagConstraints buttonConstraints = new GridBagConstraints();
        buttonConstraints.fill = GridBagConstraints.HORIZONTAL;
        buttonConstraints.anchor = GridBagConstraints.SOUTH;
        buttonConstraints.gridwidth = GridBagConstraints.REMAINDER;
        buttonConstraints.insets = new Insets(5, 5, 5, 5);

        JPanel btnPanel = showButtons(form);
        form.add(btnPanel, buttonConstraints);
        form.setEnabled(true);

        formDialog = FormPanel.showDialog(null, form, "Set CAP File", new Dimension(500, 200), null);

        formDialog.setMinimumSize(new Dimension(500, 200));

        formDialog.setVisible(true);

        setRunState(ScriptRunStates.TESTSCRIPTS);
        try {
            if (capFilePath != null) {
                loadPackage(capFilePath);
                isSuccess = true;
            } else {
                log(LogLineType.TRACE, "No cap file selected.");
            }
        } catch (Exception e) {
            // TODO Auto-generated catch block
            log(LogLineType.TRACE, "Error: " + e.toString());
        }

        setRunState(ScriptRunStates.RESULT);

        log(LogLineType.RESULT, isSuccess ? ScriptResults.PASS.toString()
                                          : ScriptResults.FAILED.toString());
    }

    public void actionPerformed(ActionEvent event) {
        String action = event.getActionCommand();

        if (action.equals(SUBMIT)) {

            try {
                formDialog.setVisible(false);
                formDialog.dispose();
            } catch (Exception e) {
                log(LogLineType.TRACE, "Error:" + e.toString());
            }
        } else if (action.equals(BROWSE)) {
            capFilePath = selectPath();
            form.getField(SELECT_CAP_FILE).setText(capFilePath);
        }
    }

    private JPanel setConfigurationPanel(FormPanel form) {

        String[] labels = { SELECT_CAP_FILE };
        int[] widths = { 300 };// no of columns
        String[] descs = { SELECT_CAP_FILE };
        String[] reqdFields = { "*" };
        JPanel panel = form.setFormLayout(labels, reqdFields, widths, descs);
        Dimension panelDimension = new Dimension(460, 100);
        panel.setMinimumSize(panelDimension);
        panel.setPreferredSize(panelDimension);
        return panel;

    }

    private JPanel showButtons(FormPanel form) {
        // add browse button

        JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        panel.setSize(400, 25);

        JButton browseBtn = form.createButton(BROWSE, BROWSE, this);
        panel.add(browseBtn);

        JButton saveBtn = form.createButton(SUBMIT, SUBMIT, this);
        panel.add(saveBtn);

        return panel;
    }

    private void loadPackage(String capFile) throws Exception {
        // Get the card reader type and establish connection to the ISO and SWP interfaces.
        CardReaderTestComponent cardType = (CardReaderTestComponent)getInstanceOfTestComponent("cardreader") ;
        if (null == cardType)
            throw new Exception("Script error: no card reader selected.") ;

        CardInterface isoReader = cardType.getCardInterface("iso") ;
        if (null == isoReader)
            throw new Exception("Script error: no card detected.") ;

        // Extract the card details.
        // Get a reference to the SIM card.
        CardDetailsTestComponent cardComponent  = (CardDetailsTestComponent)getInstanceOfTestComponent("carddetails.loksim");
        CardDetails cardDetails = cardComponent.getCardDetails() ;

        VMPADetails vmpaDetails = cardComponent.getVmpaDetails();

        // Create a new instance of the GP_SCP using the card details to extract the relevant information.
        GP_SCP sChannel = new GP_SCP(cardDetails) ;

        // Open a channel to the card manager.
        try {
            sChannel.open(isoReader, cardDetails.getSID(), cardDetails.getDefaultKvn(), 0, GPConstants.SCP_ANY, cardDetails.getSecurityLevel());

            // Create an instance of the GP loader.
            GPLoader gpLoader = new GPLoader(sChannel, false);

            // Load the package - will automatically delete the package if it's already there..
            String packageAid = gpLoader.loadPackage(capFile, false);
            
            // Install parameters require for the G&D Scorpius.
            String installParamaters = "C900" ;
        } finally {
            // Close the secure channel.
            if (null != sChannel)
                sChannel.close();

            // Reset the card.
            if (null != isoReader) {
                try {
                    isoReader.reset() ;
                } catch (Exception e) {
                }

                // Release the card.
                try {
                    isoReader.close() ;
                } catch (Exception e) {
                }
            }
        }
    }

    public String selectPath() {
        String path = null;
        FileSystemView fsv = new FileSystemView() {

            public File createNewFolder(File containingDir) throws IOException {
                return null;
            }
        };

        JFileChooser fileChooser = new JFileChooser(fsv.getDefaultDirectory());
        fileChooser.setAcceptAllFileFilterUsed(false);
        fileChooser.setFileFilter(new FileFilter() {

            public boolean accept(File pathname) {
//                System.out.println("File ==> " + pathname.getName() + " ==> " + pathname.getName().endsWith(".cap") + " ==> " + ((pathname != null) && (pathname.isDirectory() || pathname.getName().endsWith(".cap"))));
                return ((pathname != null) && (pathname.isDirectory() || pathname.getName().endsWith(".cap")));
            }

            public String getDescription(){
                return "CAP file";
            }
        });

        String title = "Set CAP File";

        fileChooser.setDialogTitle(title);

        int selectedValue = fileChooser.showDialog(null, title);

        if (selectedValue == JFileChooser.APPROVE_OPTION) {
                path = fileChooser.getSelectedFile().getPath();
        }
        return path;
    }
}
