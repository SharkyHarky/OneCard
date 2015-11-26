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
public class Create_Card_BigTrack3 extends JacketTest {

    public Create_Card_BigTrack3(ScriptManager scriptmanager) {
        super(scriptmanager);
        scriptName              = "Create Card - Track 3";
        scriptDescription       = "Verify that a card can be created with encrypted data and Tack 1 and 2 data.";
    }

    public void runTest() throws Exception
    {
        byte [] commandData = new byte [RSA_KEY_SIZE] ;

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

        Arrays.fill(commandData, (byte)0xFF) ;

        offset = 0 ;
        System.arraycopy(cid,         0, commandData, offset, cid.length) ;
        offset += (cid.length + 1) ;

        offset = TLVBuilder.putByteTLV(STATE,         (byte)1,  commandData, offset) ;
        offset = TLVBuilder.putTLV(    UI_STRING,     uiString, commandData, offset) ;
        offset = TLVBuilder.putTLV(    TRACK_3,       track3,   commandData, offset) ;
        offset = TLVBuilder.putTLV(    CARD_AID,      aid,      commandData, offset) ;
        offset = TLVBuilder.putTLV(    LABEL,         label,    commandData, offset) ;
        offset = TLVBuilder.putTLV(    PAN,           pan,      commandData, offset) ;
        offset = TLVBuilder.putTLV(    CVV,           cvv,      commandData, offset) ;
        offset = TLVBuilder.putTLV(    EXP_DATE,      expDate,  commandData, offset) ;
        offset = TLVBuilder.putByteTLV(CATEGORY,      (byte)2,  commandData, offset) ;
        offset = TLVBuilder.putByteTLV(PURPOSE,       (byte)3,  commandData, offset) ;
        offset = TLVBuilder.putByteTLV(IMAGE,         (byte)4,  commandData, offset) ;

        // Stick in the length.
        commandData[3] = (byte)(offset - 4) ;

        commandData = rsaEncrypt(commandData) ;

        // Issue the create a payment card (encrypted) APDU.
        response = isoReader.sendApdu(0x80, 0xB6, 0x01, 0x01, commandData, 0) ;

        int status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
            throw new Exception ("ERROR when creating a card: " + Integer.toHexString(status)) ;

        // Issue the read a payment card UI data.
        response = isoReader.sendApdu(0x80, 0xBC, 0x00, 0x00, cid, 0) ;
        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
            throw new Exception ("ERROR when getting a card: " + Integer.toHexString(status)) ;

        String readingCard = ByteArray.bytesToHexString(response, 0, response.length - 2, "") ;

        if (!readingCard.equals("010101020D00000000000000000000000000"))
            throw new Exception("ERROR: faile to read the card correctly: " + readingCard) ;

        // Issue the read a payment card UI data.
        response = isoReader.sendApdu(0x80, 0xBC, 0x01, 0x00, cid, 0) ;
        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
            throw new Exception ("ERROR when getting a card: " + Integer.toHexString(status)) ;

       readingCard = ByteArray.bytesToHexString(response, 0, response.length - 2, "") ;

        if (!readingCard.equals("06101010101010101010101010101010101007202020202020202020202020202020202020202020202020202020202020202020"))
            throw new Exception("ERROR: faile to read the card correctly: " + readingCard) ;

        // Issue the read a payment card UI data.
        response = isoReader.sendApdu(0x80, 0xBC, 0x02, 0x00, cid, 0) ;
        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
            throw new Exception ("ERROR when getting a card: " + Integer.toHexString(status)) ;

        readingCard = ByteArray.bytesToHexString(response, 0, response.length - 2, "") ;

        if (!readingCard.equals("056B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B6B"))
            throw new Exception("ERROR: faile to read the card correctly: " + readingCard) ;

        // Issue the read a payment card UI data.
        response = isoReader.sendApdu(0x80, 0xBC, 0x04, 0x00, cid, 0) ;
        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
            throw new Exception ("ERROR when getting a card: " + Integer.toHexString(status)) ;

        readingCard = ByteArray.bytesToHexString(response, 0, response.length - 2, "") ;

        if (!readingCard.equals("010101020D000000000000000000000000000B01020C01030D0104"))
            throw new Exception("ERROR: faile to read the card correctly: " + readingCard) ;

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

        if (!readingCard.equals("0810313233343433323131323334343332310904313233340A0531323D333400"))
            throw new Exception("ERROR: faile to read the card correctly: " + readingCard) ;
    }

}
