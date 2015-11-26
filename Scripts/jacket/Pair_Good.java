package com.radiius.jacket.scripts;

import java.util.Arrays;

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
public class Pair_Good extends JacketTest {

    public Pair_Good(ScriptManager scriptmanager) {
        super(scriptmanager);
        scriptName              = "Pair - Good";
        scriptDescription       = "Verify that a standard pairing (not the first) is handled okay.";

    }

	public void runTest() throws Exception
	{
		byte [] commandData = new byte [RSA_KEY_SIZE] ;
		Arrays.fill(commandData, (byte)0xFF) ;

		int offset = 0 ;
		commandData[offset++] = (byte)deviceFp.length ;
		System.arraycopy(deviceFp, 0, commandData, offset, deviceFp.length) ;
		offset += deviceFp.length ;

		// Encrypt with the public key.
		commandData = rsaEncrypt(commandData) ;

		// Select the card applet.
        byte [] response = isoReader.sendApdu(0x00, 0xA4, 0x04, 0x00, ByteArray.hexStrToBytes(INSTANCE_AID), 0) ;

        // Issue the initial pairing APDU.
        response = isoReader.sendApdu(0x80, 0xC2, 0x00, 0x00, commandData, 0) ;

        int status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
        	throw new Exception ("ERROR when verifying PIN: " + Integer.toHexString(status)) ;

        // Issue the second pairing APDU.
        response = isoReader.sendApdu(0x80, 0xC2, 0x00, 0x00, commandData, 0) ;

        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
        {
        	log(LogLineType.RESULT, "ERROR when verifying PIN: " + Integer.toHexString(status)) ;
        	throw new Exception ("ERROR when verifying PIN: " + Integer.toHexString(status)) ;
        }

	}

}
