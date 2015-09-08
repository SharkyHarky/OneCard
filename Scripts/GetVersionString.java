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
import com.helixion.lok.utils.ByteArray;
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
public class GetVersionString extends JavaScript implements TestScriptConstants {

	private static String INSTANCE_AID = "5241440000010011" ;

    public GetVersionString(ScriptManager scriptmanager) {
        super(scriptmanager);
    }

    /* (non-Javadoc)
     * @see com.helixion.lok.scripts.Script#getName()
     */
    public String getName() {
        return "Get Version";
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
        return "Retrieves the version string of the applet." ;
    }

    /* (non-Javadoc)
     * @see com.helixion.lok.scripts.Script#getScriptType()
     */
    public ScriptTypes getScriptType() {
        return ScriptTypes.UTILITY;
    }

    public void run() {
        boolean isSuccess = false;
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

            // Select the card applet.
            byte [] response = isoReader.sendApdu(0x00, 0xA4, 0x04, 0x00, ByteArray.hexStrToBytes(INSTANCE_AID), 0) ; 

            // Issue the put data commands to the applet.
            response = isoReader.sendApdu(0x80, 0xCA, 0x40, 0x00, null, 0) ;
            
            int status = ByteArray.getShortBE(response, response.length - 2) ;
            if (status == 0x9000)
            	log(LogLineType.RESULT, "Version string: " + new String(response, 3, response.length - 5)) ;
            else
            	log(LogLineType.RESULT, "ERROR when reading version string: " + Integer.toHexString(status)) ;

            isSuccess = true;
            
        }
        catch (Exception e)
        {
            log(LogLineType.TRACE, "Error: " + e.toString());
        }
        finally
        {
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
