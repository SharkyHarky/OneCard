package com.radiius.card.scripts;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javacard.framework.Util;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.helixion.globalplatform.GPConstants;
import com.helixion.globalplatform.GPLoader;
import com.helixion.globalplatform.GP_SCP;
import com.helixion.lok.logger.LogLineType;
import com.helixion.lok.scriptmanager.ScriptManager;
import com.helixion.lok.scripts.JavaScript;
import com.helixion.lok.scripts.ScriptResults;
import com.helixion.lok.scripts.ScriptRunStates;
import com.helixion.lok.scripts.ScriptTypes;
import com.helixion.lok.testcomponent.carddetails.CardDetails;
import com.helixion.lok.testcomponent.carddetails.CardDetailsTestComponent;
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
public abstract class CardTest extends JavaScript  {

	protected static int    AES_KEY_LENGTH = 32 ;
	protected static final byte [] aesMKey    = {1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 5, 6} ;

	private   static String PACKAGE_AID  = "524144000001" ;
	protected static String APPLET_AID   = "5241440000010011" ;
	protected static String INSTANCE_AID = "524144000001001101" ;

	// Fields that will be personalised.
	protected static final byte [] cardHash   = {1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1, 2} ;
	protected static final byte [] jacketHash = {1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 3, 4} ;

    /**
     * These attributes are set by the test case that implements this abstract
     * class.
     */
    protected String                  scriptName              = "No Name";
    protected String                  scriptDescription       = "No Description";

    protected CardInterface           isoReader = null;

    private   GP_SCP                  sChannel = null;

    protected boolean                 stoppedTest             = false;

    public CardTest(ScriptManager scriptmanager) {
        super(scriptmanager);
    }

    /* (non-Javadoc)
     * @see com.helixion.lok.scripts.Script#getPackage()
     */
    public String[] getPackageTree() {
        return new String[] {"Radiius", "Card"} ;
    }

    /* (non-Javadoc)
     * @see com.helixion.lok.scripts.Script#getName()
     */
    public String getName() {
        return scriptName ;
    }

    /* (non-Javadoc)
     * @see com.helixion.lok.scripts.Script#getDescription()
     */
    public String getDescription() {
        return scriptDescription ;
    }

    /* (non-Javadoc)
     * @see com.helixion.lok.scripts.Script#getScriptType()
     */
    public ScriptTypes getScriptType() {
        return ScriptTypes.PROTECTED;
    }

    /**
     * This is the method that implements the test.
     * <p>
     * It is invoked from the <code>run()</code> method and must throw an
     * exception if it detects a failure when running the script.
     *
     * @throws Exception
     *             if an error is detected when running the script.
     */
    public abstract void runTest() throws Exception;

    /* (non-Javadoc)
     * @see com.helixion.lok.scripts.JavaScript#run()
     */
    public void run()
    {
        boolean isSuccess = true;
        stoppedTest = false;
        setRunState(ScriptRunStates.PRECONDITIONS);

        try
        {
            setRunState(ScriptRunStates.TESTSCRIPTS);

        	// Delete the card and re-perso.
            initialise();

            // Run the test script - it will throw an exception if an error is detected.
            this.runTest();
        }
        catch (Exception e)
        {
            isSuccess = false;

            log(LogLineType.TRACE, "Error: " + e.getMessage());
        }
        finally
        {
            setRunState(ScriptRunStates.POSTCONDITIONS);

            setRunState(ScriptRunStates.RESULT);

            // Post the test result - unless the test was cancelled half way
            // through.
            if (stoppedTest)
            {
                log(LogLineType.RESULT, ScriptResults.TERMINATED.toString());
            }
            else
            {
                log(LogLineType.RESULT,
                    isSuccess ? ScriptResults.PASS.toString()
                             : ScriptResults.FAILED.toString());
            }

            finalise();
        }
    }

    public void initialise() throws Exception {

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
                gpLoader.deleteAID(INSTANCE_AID, false);
            }

            try {
                gpLoader.deleteAID(APPLET_AID, false);
            } catch (Exception e) {
                gpLoader.deleteAID(APPLET_AID, false);
            }

            // Install a new instance.
            gpLoader.installApplet(PACKAGE_AID, APPLET_AID, INSTANCE_AID, 0, null, null) ;

            // Open a secure channel to the VMPA instance.
            sChannel.open(isoReader, INSTANCE_AID, cardDetails.getDefaultKvn(), 0, GPConstants.SCP_ANY, GPConstants.APDU_MAC);

            // Issue the put data commands to the applet.
            sChannel.sendApdu(0x80, 0xDA, 0x00, 0x01, cardHash, 0) ;
            sChannel.sendApdu(0x80, 0xDA, 0x00, 0x02, jacketHash, 0) ;
            sChannel.sendApdu(0x80, 0xDA, 0x80, 0x04, aesMKey, 0) ;
        }
        finally
        {
            // Close the secure channel.
            if (null != sChannel)
                sChannel.close();
        }
    }

    public void finalise()
    {
        // Close the secure channel.
        if (null != sChannel)
            sChannel.close();

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
        isoReader = null ;
    }

    protected byte[] encrypt(int random, byte[] plainText) throws Exception
	{
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		SecretKeySpec keySpec = setSessionKey(random) ;
		byte[] iv = new byte[16];
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
		return cipher.doFinal(plainText);
	}

	protected byte[] decrypt(int random, byte[] cipherText) throws Exception
	{
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		SecretKeySpec keySpec = setSessionKey(random) ;
		byte[] iv = new byte[16];
		cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
		return cipher.doFinal(cipherText) ;
	}

	private SecretKeySpec setSessionKey(int random) throws Exception {

		byte [] tmpBuffer = new byte[AES_KEY_LENGTH];

		// Initialise the key derivation data to all 0.
		Arrays.fill(tmpBuffer, (byte)0) ;

		// Write the RND at the start of the buffer.
		ByteArray.putShortBE( random, tmpBuffer, 0) ;
		ByteArray.putShortBE((~random & 0xFFFF), tmpBuffer, AES_KEY_LENGTH >> 1) ;

		// Encrypt using the master key.
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		SecretKeySpec keySpec = new SecretKeySpec(aesMKey, "AES");
		byte[] iv = new byte[16];
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));

		// Encrypt using the master key.
		tmpBuffer = cipher.doFinal(tmpBuffer) ;

		return new SecretKeySpec(tmpBuffer, "AES");
	}


}
