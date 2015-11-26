package com.radiius;

import com.helixion.globalplatform.GPConstants;
import com.helixion.globalplatform.GPLoader;
import com.helixion.globalplatform.GP_SCP;
import com.helixion.lok.logger.LogLineType;
import com.helixion.lok.lokSimTester.scriptutils.TestScriptConstants;
import com.helixion.lok.scriptmanager.ScriptManager;
import com.helixion.lok.scripts.JavaScript;
import com.helixion.lok.scripts.ScriptResults;
import com.helixion.lok.scripts.ScriptRunStates;
import com.helixion.lok.scripts.ScriptTypes;
import com.helixion.lok.testcomponent.carddetails.CardDetails;
import com.helixion.lok.testcomponent.carddetails.CardDetailsTestComponent;
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
public class DeleteAll extends JavaScript implements TestScriptConstants {

    public DeleteAll(ScriptManager scriptmanager) {
        super(scriptmanager);
    }

    /* (non-Javadoc)
     * @see com.helixion.lok.scripts.Script#getName()
     */
    public String getName() {
        return "Delete all";
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
        return "Deletes all Radiius file and applets." ;
    }

    /* (non-Javadoc)
     * @see com.helixion.lok.scripts.Script#getScriptType()
     */
    public ScriptTypes getScriptType() {
        return ScriptTypes.UTILITY;
    }

    public void run() {
         boolean isSuccess = false;
         CardInterface isoReader = null ;
         GP_SCP sChannel = null ;

        setRunState(ScriptRunStates.TESTSCRIPTS);
        try {
            // Get the card reader type and establish connection to the ISO and SWP interfaces.
            CardReaderTestComponent cardType = (CardReaderTestComponent)getInstanceOfTestComponent("cardreader") ;
            if (null == cardType)
                throw new Exception("Script error: no card reader selected.") ;

            isoReader = cardType.getCardInterface("iso") ;
            if (null == isoReader)
                throw new Exception("Script error: no card detected.") ;

            // Extract the card details.
            // Get a reference to the SIM card.
            CardDetailsTestComponent cardComponent  = (CardDetailsTestComponent)getInstanceOfTestComponent("carddetails.loksim");
            CardDetails cardDetails = cardComponent.getCardDetails() ;

            // Create a new instance of the GP_SCP using the card details to extract the relevant information.
            sChannel = new GP_SCP(cardDetails) ;

            // Open a channel to the card manager.
            sChannel.open(isoReader, cardDetails.getSID(), cardDetails.getDefaultKvn(), 0, GPConstants.SCP_ANY, cardDetails.getSecurityLevel());

            // Create an instance of the GP loader.
            GPLoader gpLoader = new GPLoader(sChannel, false);

            gpLoader.deleteAID("524143000000", true) ;
            gpLoader.deleteAID("524144000000", true) ;
            gpLoader.deleteAID("524143000001", true) ;
            gpLoader.deleteAID("524144000001", true) ;

            isSuccess = true;
        } catch (Exception e) {
            // TODO Auto-generated catch block
            log(LogLineType.TRACE, "Error: " + e.toString());
        }
        finally {
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
        setRunState(ScriptRunStates.RESULT);

        log(LogLineType.RESULT, isSuccess ? ScriptResults.PASS.toString()
                                          : ScriptResults.FAILED.toString());
    }

}
