package com.radiius.jacket.scripts;

import java.util.Arrays;

import com.helixion.globalplatform.GPConstants;
import com.helixion.globalplatform.GP_SCP;
import com.helixion.lok.scriptmanager.ScriptManager;
import com.helixion.lok.testcomponent.carddetails.CardDetails;
import com.helixion.lok.testcomponent.carddetails.CardDetailsTestComponent;
import com.helixion.lok.utils.ByteArray;

/**
 * This test has to trigger an CDI check in the PM.
 *
 * As it's the first one after personalisation and the IURO has been set to
 * trigger a interval based Issuer Update this should fire off an Issuer Update.
 *
 * @author Steve Harkins
 */
public class Unblock_Pin extends JacketTest {

    public Unblock_Pin(ScriptManager scriptmanager) {
        super(scriptmanager);
        scriptName              = "Unblock PIN";
        scriptDescription       = "Test that PIN is blocked after 3 wrong attempts. Then verify that the PIN can be unblocked by a Radiius server script." ;
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

		// Use the new PIN that hasn't been loaded.
		commandData[offset++] = (byte)newPin.length ;
		System.arraycopy(newPin, 0, commandData, offset, newPin.length) ;
		offset += newPin.length ;

		// Encrypt with the public key.
		commandData = rsaEncrypt(commandData) ;

		// Select the card applet.
        byte [] response = isoReader.sendApdu(0x00, 0xA4, 0x04, 0x00, ByteArray.hexStrToBytes(INSTANCE_AID), 0) ;

        // Issue the validate APDU.
        response = isoReader.sendApdu(0x80, 0xB0, 0x00, 0x00, commandData, 0) ;

        // First off block the PIN  by putting in three wrong entries.
        int status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x63C2)
        	throw new Exception ("ERROR expected a retry (2) got: " + Integer.toHexString(status)) ;

        // Issue the validate APDU.
        response = isoReader.sendApdu(0x80, 0xB0, 0x00, 0x00, commandData, 0) ;

        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x63C1)
        	throw new Exception ("ERROR expected a retry (1) got: " + Integer.toHexString(status)) ;

        // Issue the validate APDU.
        response = isoReader.sendApdu(0x80, 0xB0, 0x00, 0x00, commandData, 0) ;

        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x63C0)
        	throw new Exception ("ERROR expected a retry (0) got: " + Integer.toHexString(status)) ;

        // Then do a good one to show that it is blocked.
		Arrays.fill(commandData, (byte)0xFF) ;

		offset = 0 ;
		commandData[offset++] = (byte)deviceFp.length ;
		System.arraycopy(deviceFp, 0, commandData, offset, deviceFp.length) ;
		offset += deviceFp.length ;

		commandData[offset++] = (byte)jacketPin.length ;
		System.arraycopy(jacketPin, 0, commandData, offset, jacketPin.length) ;
		offset += jacketPin.length ;

		// Encrypt with the public key.
		commandData = rsaEncrypt(commandData) ;

        // Issue the validate APDU.
        response = isoReader.sendApdu(0x80, 0xB0, 0x00, 0x00, commandData, 0) ;

        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x6983)
        	throw new Exception ("ERROR when verifying PIN: " + Integer.toHexString(status)) ;

        // Now set up a secure channel with the Jacket Applet to unblock.
        CardDetailsTestComponent cardComponent  = (CardDetailsTestComponent)getInstanceOfTestComponent("carddetails.loksim");
        CardDetails cardDetails = cardComponent.getCardDetails() ;

        // Create a new instance of the GP_SCP using the card details to extract the relevant information.
        GP_SCP sChannel = new GP_SCP(cardDetails) ;

        // Open a secure channel to the VMPA instance.
        sChannel.open(isoReader, INSTANCE_AID, cardDetails.getDefaultKvn(), 0, GPConstants.SCP_ANY, GPConstants.APDU_MAC);

        // Issue the unblock PIN with the new PIN value.
        response = sChannel.sendApdu(0x80, 0xB2, 0x00, 0x00, newPin, 0) ;

        // Close the secure channel.
        sChannel.close();

		// Select the card applet.
        response = isoReader.sendApdu(0x00, 0xA4, 0x04, 0x00, ByteArray.hexStrToBytes(INSTANCE_AID), 0) ;

		Arrays.fill(commandData, (byte)0xFF) ;

		offset = 0 ;
		commandData[offset++] = (byte)deviceFp.length ;
		System.arraycopy(deviceFp, 0, commandData, offset, deviceFp.length) ;
		offset += deviceFp.length ;

		// Use the new PIN that hasn't been loaded.
		commandData[offset++] = (byte)newPin.length ;
		System.arraycopy(newPin, 0, commandData, offset, newPin.length) ;
		offset += newPin.length ;

		// Encrypt with the public key.
		commandData = rsaEncrypt(commandData) ;

		// Issue the verify PIN with the new PIN value.
        response = isoReader.sendApdu(0x80, 0xB0, 0x00, 0x00, commandData, 0) ;

        // First off block the PIN  by putting in three wrong entries.
        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
        	throw new Exception ("ERROR expected invalid status: " + Integer.toHexString(status)) ;

	}

}
