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
public class Pair_Bad extends JacketTest {

    public Pair_Bad(ScriptManager scriptmanager) {
        super(scriptmanager);
        scriptName              = "Pairing - Bad";
        scriptDescription       = "Verify that the applet detects pairing attempted with incorrect data.";

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
        response = isoReader.sendApdu(0x80, 0xc2, 0x00, 0x00, commandData, 0) ;

        int status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
        {
        	log(LogLineType.RESULT, "ERROR when pairing: " + Integer.toHexString(status)) ;
        	throw new Exception ("ERROR when pairing: " + Integer.toHexString(status)) ;
        }

        // Corrupt the data
        commandData[100] = (byte)~commandData[100];

        // Issue the next pairing with corrupt data
        response = isoReader.sendApdu(0x80, 0xc2, 0x00, 0x00, commandData, 0) ;

        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x6986)
        {
        	log(LogLineType.RESULT, "ERROR expected a status of 6986 but got: " + Integer.toHexString(status)) ;
        	throw new Exception ("ERROR expected a status of 6986 but got: " + Integer.toHexString(status)) ;
        }

	}

}
