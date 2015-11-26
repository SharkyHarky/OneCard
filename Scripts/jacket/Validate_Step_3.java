package com.radiius.jacket.scripts;

import com.helixion.lok.logger.LogLineType;
import com.helixion.lok.scriptmanager.ScriptManager;
import com.helixion.lok.utils.ByteArray;

/**
 * This test has to trigger an CDI check in the PM.
 *
 * As it's the first one after personalisation and the IURO has been set to
 * trigger a interval based Issuer Update this should fire off an Issuer Update.
 *
 * @author Steve Harkins
 */
public class Validate_Step_3 extends JacketTest {

    public Validate_Step_3(ScriptManager scriptmanager) {
        super(scriptmanager);
        scriptName              = "Good Validate Step 3";
        scriptDescription       = "Verify that encrypted card hash returned by the Jacket SE correctly.";

    }

	public void runTest() throws Exception
	{
		int counter = 42 ;
		byte [] hashes = new byte [cardHash.length + jacketHash.length] ;
		System.arraycopy(cardHash,    0, hashes, 0,                 cardHash.length) ;
		System.arraycopy(jacketHash,  0, hashes, cardHash.length,  jacketHash.length) ;

		byte[] encHashes = encrypt(counter, hashes) ;

		byte [] commandData = new byte [encHashes.length + 2] ;
		ByteArray.putShortBE( counter, commandData, 0) ;
		System.arraycopy(encHashes, 0, commandData, 2, encHashes.length) ;

        // Select the card applet.
        byte [] response = isoReader.sendApdu(0x00, 0xA4, 0x04, 0x00, ByteArray.hexStrToBytes(INSTANCE_AID), 0) ;

        // Issue the validate APDU.
        response = isoReader.sendApdu(0x80, 0xC0, 0x02, 0x00, commandData, 0) ;

        int status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
        {
        	log(LogLineType.RESULT, "ERROR when validating: " + Integer.toHexString(status)) ;
        	throw new Exception ("ERROR when validating: " + Integer.toHexString(status)) ;
        }

        if (response.length > 2)
        {
        	log(LogLineType.RESULT, "ERROR didn't expect data back, got: " + ByteArray.bytesToHexString(response, 0, response.length - 2, "")) ;
        	throw new Exception ("ERROR didn't expect data back, got: " + ByteArray.bytesToHexString(response, 0, response.length - 2, "")) ;
        }
    }

}
