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
public class Change_Pin_Good extends JacketTest {

    public Change_Pin_Good(ScriptManager scriptmanager) {
        super(scriptmanager);
        scriptName              = "Good Change Verify";
        scriptDescription       = "Test that PIN is validated correctly.";

    }

	public void runTest() throws Exception
	{
		byte [] newPin  = {0x35, 0x34, 0x33, 0x32, 0x31} ;

		byte [] commandData = new byte [RSA_KEY_SIZE] ;
		Arrays.fill(commandData, (byte)0xFF) ;

		int offset = 0 ;
		commandData[offset++] = (byte)deviceFp.length ;
		System.arraycopy(deviceFp, 0, commandData, offset, deviceFp.length) ;
		offset += deviceFp.length ;

		commandData[offset++] = (byte)jacketPin.length ;
		System.arraycopy(jacketPin, 0, commandData, offset, jacketPin.length) ;
		offset += jacketPin.length ;

		// Encrypt with the public key.
		commandData = rsaEncrypt(commandData) ;

		// Select the card applet.
        byte [] response = isoReader.sendApdu(0x00, 0xA4, 0x04, 0x00, ByteArray.hexStrToBytes(INSTANCE_AID), 0) ;

        // Issue the verify PIN APDU - old PIN.
        response = isoReader.sendApdu(0x80, 0xB0, 0x00, 0x00, commandData, 0) ;

        int status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
        {
        	log(LogLineType.RESULT, "ERROR when verifying PIN: " + Integer.toHexString(status)) ;
        	throw new Exception ("ERROR when verifying PIN: " + Integer.toHexString(status)) ;
        }

		offset = 0 ;
		Arrays.fill(commandData, (byte)0xFF) ;
		commandData[offset++] = (byte)deviceFp.length ;
		System.arraycopy(deviceFp, 0, commandData, offset, deviceFp.length) ;
		offset += deviceFp.length ;

		commandData[offset++] = (byte)jacketPin.length ;
		System.arraycopy(jacketPin, 0, commandData, offset, jacketPin.length) ;
		offset += jacketPin.length ;

		commandData[offset++] = (byte)newPin.length ;
		System.arraycopy(newPin, 0, commandData, offset, newPin.length) ;
		offset += newPin.length ;

		// Encrypt with the public key.
		commandData = rsaEncrypt(commandData) ;

        // Issue the change PIN APDU.
        response = isoReader.sendApdu(0x80, 0xB4, 0x00, 0x00, commandData, 0) ;

        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
        {
        	log(LogLineType.RESULT, "ERROR when changing PIN: " + Integer.toHexString(status)) ;
        	throw new Exception ("ERROR when changing PIN: " + Integer.toHexString(status)) ;
        }

		Arrays.fill(commandData, (byte)0xFF) ;

		offset = 0 ;
		commandData[offset++] = (byte)deviceFp.length ;
		System.arraycopy(deviceFp, 0, commandData, offset, deviceFp.length) ;
		offset += deviceFp.length ;

		commandData[offset++] = (byte)newPin.length ;
		System.arraycopy(newPin, 0, commandData, offset, newPin.length) ;
		offset += newPin.length ;

		// Encrypt with the public key.
		commandData = rsaEncrypt(commandData) ;

        // Issue the verify PIN APDU - new PIN.
        response = isoReader.sendApdu(0x80, 0xB0, 0x00, 0x00, commandData, 0) ;

        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
        {
        	log(LogLineType.RESULT, "ERROR when verifying PIN: " + Integer.toHexString(status)) ;
        	throw new Exception ("ERROR when verifying PIN: " + Integer.toHexString(status)) ;
        }

	}

}
