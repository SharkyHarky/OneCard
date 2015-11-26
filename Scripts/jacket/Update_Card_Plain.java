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
public class Update_Card_Plain extends JacketTest {

    public Update_Card_Plain(ScriptManager scriptmanager) {
        super(scriptmanager);
        scriptName              = "Update Card - plain";
        scriptDescription       = "Verify that a card can be updated with plaintext data.";
    }

    public void runTest() throws Exception
    {
        byte [] cid = {1,2,3} ;
        byte [] uiString = new byte [13] ;
        byte [] pan = ByteArray.hexStrToBytes("1234432112344321") ;
        byte [] commandData = new byte [100] ;
        Arrays.fill(commandData, (byte)0xFF) ;

        int offset = 0 ;
        System.arraycopy(cid,         0, commandData, offset, cid.length) ;
        offset += (cid.length + 1) ;

//        offset = TLVBuilder.putByteTLV(STATE,     (byte)0,  commandData, offset) ;
        offset = TLVBuilder.putTLV(    UI_STRING, uiString, commandData, offset) ;

        // Stick in the length.
        commandData[3] = (byte)(offset - 4) ;

        byte [] cardTlv = new byte [offset] ;
        System.arraycopy(commandData, 0, cardTlv, 0, cardTlv.length) ;

        // Select the card applet.
        byte [] response = isoReader.sendApdu(0x00, 0xA4, 0x04, 0x00, ByteArray.hexStrToBytes(INSTANCE_AID), 0) ;

        // Issue the create a basic payment card APDU.
        response = isoReader.sendApdu(0x80, 0xB6, 0x01, 0x00, cardTlv, 0) ;

        int status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
        {
            log(LogLineType.RESULT, "ERROR when creating a card: " + Integer.toHexString(status)) ;
            throw new Exception ("ERROR when creating a card: " + Integer.toHexString(status)) ;
        }

        // Issue the read a payment card UI data.
        response = isoReader.sendApdu(0x80, 0xBC, 0x04, 0x00, cid, 0) ;

        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
        {
            log(LogLineType.RESULT, "ERROR when getting a card: " + Integer.toHexString(status)) ;
            throw new Exception ("ERROR when getting a card: " + Integer.toHexString(status)) ;
        }

        String readingCard = ByteArray.bytesToHexString(response, 0, response.length - 2, "") ;

        if (!readingCard.equals("010100020D00000000000000000000000000"))
            throw new Exception("ERROR: fail to read the card correctly: " + readingCard) ;

        Arrays.fill(commandData, (byte)0xFF) ;
        offset = 0 ;
        System.arraycopy(cid,         0, commandData, offset, cid.length) ;
        offset += (cid.length + 1) ;

        offset = TLVBuilder.putByteTLV(STATE,     (byte)1,  commandData, offset) ;
        offset = TLVBuilder.putByteTLV(CATEGORY,  (byte)2,  commandData, offset) ;
        offset = TLVBuilder.putByteTLV(PURPOSE,   (byte)3,  commandData, offset) ;
        offset = TLVBuilder.putByteTLV(IMAGE,     (byte)4,  commandData, offset) ;

        cardTlv = new byte [offset] ;
        System.arraycopy(commandData, 0, cardTlv, 0, cardTlv.length) ;

        // Issue the APDU to update the card.
        response = isoReader.sendApdu(0x80, 0xB8, 0x01, 0x00, cardTlv, 0) ;

        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
        {
            log(LogLineType.RESULT, "ERROR when creating a card: " + Integer.toHexString(status)) ;
            throw new Exception ("ERROR when creating a card: " + Integer.toHexString(status)) ;
        }

        // Issue the read a payment card UI data.
        response = isoReader.sendApdu(0x80, 0xBC, 0x04, 0x00, cid, 0) ;

        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
        {
            log(LogLineType.RESULT, "ERROR when getting a card: " + Integer.toHexString(status)) ;
            throw new Exception ("ERROR when getting a card: " + Integer.toHexString(status)) ;
        }

        readingCard = ByteArray.bytesToHexString(response, 0, response.length - 2, "") ;

        if (!readingCard.equals("010101020D000000000000000000000000000B01020C01030D0104"))
            throw new Exception("ERROR: faile to read the card correctly: " + readingCard) ;

    }

}
