package com.radiius.card.scripts;

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
public class InstallAndPerso extends JavaScript implements TestScriptConstants {

	private static String PACKAGE_AID  = "524144000001" ;
	private static String INSTANCE_AID = "5241440000010011" ;

	private static final byte [] cardHash   = {1,2,3,4,5,6,7,8,9,0} ;
	private static final byte [] sleeveHash = {1,2,3,4,5,6,7,8,9,0} ;
	private static final byte [] aesMKey    = {1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,9,8} ;

    public InstallAndPerso(ScriptManager scriptmanager) {
        super(scriptmanager);
    }

    /* (non-Javadoc)
     * @see com.helixion.lok.scripts.Script#getName()
     */
    public String getName() {
        return "Instantiate the card Applet.";
    }

    /* (non-Javadoc)
     * @see com.helixion.lok.scripts.Script#getPackage()
     */
    public String[] getPackageTree() {
        return new String[] {"Radiius", "Card"} ;
    }

    /* (non-Javadoc)
     * @see com.helixion.lok.scripts.Script#getDescription()
     */
    public String getDescription() {
        return "Instantiates and personalises the card applet." ;
    }

    /* (non-Javadoc)
     * @see com.helixion.lok.scripts.Script#getScriptType()
     */
    public ScriptTypes getScriptType() {
        return ScriptTypes.UTILITY;
    }

    public void run() {
        boolean isSuccess = false;
        GP_SCP sChannel = null;
        CardInterface isoReader = null;
        setRunState(ScriptRunStates.RESULT);

        try
        {
            // Get the card reader type and establish connection to the ISO and SWP interfaces.
            CardReaderTestComponent cardType = (CardReaderTestComponent)getInstanceOfTestComponent("cardreader") ;
            if (null == cardType)
                throw new Exception("Script error: no card reader selected.") ;

            isoReader = cardType.getCardInterface("iso") ;
            if (null == isoReader)
                throw new Exception("Script error: no card detected.") ;

            // Get a reference to the SIM card.
            CardDetailsTestComponent cardComponent  = (CardDetailsTestComponent)getInstanceOfTestComponent("carddetails.loksim");
            CardDetails cardDetails = cardComponent.getCardDetails() ;

            // Create a new instance of the GP_SCP using the card details to extract the relevant information.
            sChannel = new GP_SCP(cardDetails) ;

            // Open a channel to the card manager.
            sChannel.open(isoReader,
                          cardDetails.getSID(),
                          cardDetails.getDefaultKvn(),
                          0,
                          GPConstants.SCP_ANY,
                          cardDetails.getSecurityLevel());

            // Create an instance of the GP loader.
            GPLoader gpLoader = new GPLoader(sChannel, false ) ;

            // Delete any existing instance.
            try {
                gpLoader.deleteAID(INSTANCE_AID, false);
            } catch (Exception e) {
                // Try again.
                gpLoader.deleteAID(INSTANCE_AID, false);
            }

            // Install a new instance.
            gpLoader.installApplet(PACKAGE_AID, INSTANCE_AID, INSTANCE_AID, 0x10, null, null) ;

            // Open a secure channel to the VMPA instance.
            sChannel.open(isoReader, INSTANCE_AID, cardDetails.getDefaultKvn(), 0, GPConstants.SCP_ANY, GPConstants.APDU_MAC);

            // Issue the put data commands to the applet.
            sChannel.sendApdu(0x80, 0xDA, 0x00, 0x01, cardHash, 0) ; 
            sChannel.sendApdu(0x80, 0xDA, 0x00, 0x02, sleeveHash, 0) ; 
            sChannel.sendApdu(0x80, 0xDA, 0x80, 0x04, aesMKey, 0) ; 
            
            isSuccess = true;
        }
        catch (Exception e)
        {
            log(LogLineType.TRACE, "Error: " + e.toString());
        }
        finally
        {

            // Close the secure channel.
            if (null != sChannel)
                sChannel.close();

            // Reset the card.
            if (null != isoReader)
            {
                try
                {
                    isoReader.reset();
                }
                catch (Exception e)
                {
                }
            }
        }

        setRunState(ScriptRunStates.RESULT);

        log(LogLineType.RESULT, isSuccess ? ScriptResults.PASS.toString()
                                         : ScriptResults.FAILED.toString());
    }

}
