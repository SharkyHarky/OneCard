package com.radiius.jacket.scripts;

import java.util.Arrays;

import com.helixion.lok.logger.LogLineType;
import com.helixion.lok.scriptmanager.ScriptManager;
import com.helixion.lok.utils.ByteArray;
import com.helixion.lok.utils.Tlv;
import com.radiius.TLVBuilder;

/**
 * This test has to trigger an CDI check in the PM.
 *
 * As it's the first one after personalisation and the IURO has been set to
 * trigger a interval based Issuer Update this should fire off an Issuer Update.
 *
 * @author Steve Harkins
 */
public class Update_Card_Enc extends JacketTest {

    public Update_Card_Enc(ScriptManager scriptmanager) {
        super(scriptmanager);
        scriptName              = "Update Card - encrypted";
        scriptDescription       = "Verify that a card can be updated with encrypted data.";
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

        byte [] cid = {1,2,3} ;
        byte [] pan = ByteArray.hexStrToBytes("1234432112344321") ;
        byte [] uiString = new byte [13] ;
        commandData = new byte [100] ;
        Arrays.fill(commandData, (byte)0xFF) ;

        offset = 0 ;
        System.arraycopy(cid,         0, commandData, offset, cid.length) ;
        offset += (cid.length + 1) ;

        offset = TLVBuilder.putTLV(    UI_STRING, uiString, commandData, offset) ;

        // Stick in the length.
        commandData[3] = (byte)(offset - 4) ;

        byte [] cardTlv = new byte [offset] ;
        System.arraycopy(commandData, 0, cardTlv, 0, cardTlv.length) ;

        // Issue the create a basic payment card APDU.
        response = isoReader.sendApdu(0x80, 0xB6, 0x01, 0x00, cardTlv, 0) ;

        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
            throw new Exception ("ERROR when creating a card: " + Integer.toHexString(status)) ;

        // Issue the read a payment card UI data.
        response = isoReader.sendApdu(0x80, 0xBC, 0x04, 0x00, cid, 0) ;

        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
            throw new Exception ("ERROR when getting a card: " + Integer.toHexString(status)) ;

        String readingCard = ByteArray.bytesToHexString(response, 0, response.length - 2, "") ;

        if (!readingCard.equals("010100020D00000000000000000000000000"))
            throw new Exception("ERROR: fail to read the card correctly: " + readingCard) ;

        Arrays.fill(commandData, (byte)0xFF) ;
        offset = 0 ;
        System.arraycopy(cid,         0, commandData, offset, cid.length) ;
        offset += (cid.length + 1) ;

        offset = TLVBuilder.putByteTLV(STATE,     (byte)1,  commandData, offset) ;
        offset = TLVBuilder.putTLV(    PAN,       pan,      commandData, offset) ;
        offset = TLVBuilder.putByteTLV(CATEGORY,  (byte)2,  commandData, offset) ;
        offset = TLVBuilder.putByteTLV(PURPOSE,   (byte)3,  commandData, offset) ;
        offset = TLVBuilder.putByteTLV(IMAGE,     (byte)4,  commandData, offset) ;

        cardTlv = new byte [offset] ;
        System.arraycopy(commandData, 0, cardTlv, 0, cardTlv.length) ;

        // Issue the APDU to update the card.
        response = isoReader.sendApdu(0x80, 0xB8, 0x01, 0x00, cardTlv, 0) ;

        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
            throw new Exception ("ERROR when creating a card: " + Integer.toHexString(status)) ;

//        •	The CID of the card to be retrieved
//        •	The length of the handset fingerprint
//        •	The handset fingerprint bytes
//        •	The length of the PIN
//        •	ASCII representation of the PIN
//        •	A 32 byte randomly
//        •	Padding of 0x00 out to the Jacket public key length.

        commandData = new byte [RSA_KEY_SIZE] ;
		Arrays.fill(commandData, (byte)0x00) ;

		offset = 0 ;
		System.arraycopy(cid, 0, commandData, offset, cid.length) ;
		offset += cid.length ;

		commandData[offset++] = (byte)deviceFp.length ;
		System.arraycopy(deviceFp, 0, commandData, offset, deviceFp.length) ;
		offset += deviceFp.length ;

		commandData[offset++] = (byte)jacketPin.length ;
		System.arraycopy(jacketPin, 0, commandData, offset, jacketPin.length) ;
		offset += jacketPin.length ;

		// Dummy AES key of 32 0x11's
		Arrays.fill(commandData, offset, offset+32, (byte)0x11) ;
		offset += 32 ;

		// Encrypt with the public key.
		commandData = rsaEncrypt(commandData) ;

		// Issue the read a payment card UI data.
        response = isoReader.sendApdu(0x80, 0xBC, 0x03, 0x01, commandData, 0) ;

        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
            throw new Exception ("ERROR when getting a card: " + Integer.toHexString(status)) ;

		// Encrypt with the public key.
        byte [] rsp = new byte [response.length - 2] ;
		System.arraycopy(response, 0, rsp, 0, rsp.length) ;

		rsp = decrypt(rsp) ;

        readingCard = ByteArray.bytesToHexString(rsp, "") ;

        if (!readingCard.equals("08081234432112344321000000000000"))
            throw new Exception("ERROR: faile to read the card correctly: " + readingCard) ;

    }

}
