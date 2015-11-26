package com.radiius.jacket.scripts;

import java.util.Arrays;

import com.helixion.lok.scriptmanager.ScriptManager;
import com.helixion.lok.utils.ByteArray;
import com.radiius.TLVBuilder;

/**
 * This test has to trigger an CDI check in the PM.
 *
 * As it's the first one after personalisation and the IURO has been set to
 * trigger a interval based Issuer Update this should fire off an Issuer Update.
 *
 * @author Steve Harkins
 */
public class Create_Card_Lots extends JacketTest {

    public Create_Card_Lots(ScriptManager scriptmanager) {
        super(scriptmanager);
        scriptName              = "Create Card - lots";
        scriptDescription       = "Verify that a the maximum number of cardds is handled correctly. " +
        		                  "In addition make sure the delete works as expected" ;
    }

    public void runTest() throws Exception
    {
        byte [] commandData = new byte [100] ;
        Arrays.fill(commandData, (byte)0xFF) ;

        int offset = 0 ;
        System.arraycopy(cid,         0, commandData, offset, cid.length) ;
        offset += (cid.length + 1) ;
        offset = TLVBuilder.putTLV(    UI_STRING, uiString, commandData, offset) ;

        // Stick in the length.
        commandData[3] = (byte)(offset - 4) ;

        byte [] cardTlv = new byte [offset] ;
        System.arraycopy(commandData, 0, cardTlv, 0, cardTlv.length) ;

        // Select the card applet.
        byte [] response = isoReader.sendApdu(0x00, 0xA4, 0x04, 0x00, ByteArray.hexStrToBytes(INSTANCE_AID), 0) ;

        // Loop round and create 100 cards.
        int status ;
        for (byte i = 0; i < 100; i++)
        {
            // Change the last byte of the CID
        	cardTlv[2] = i ;

        	// Change the first byte of the UI
        	cardTlv[6] = i ;

            response = isoReader.sendApdu(0x80, 0xB6, 0x01, 0x00, cardTlv, 0) ;

            status = ByteArray.getShortBE(response, response.length - 2) ;
            if (status != 0x9000)
                throw new Exception ("ERROR when creating a card: " + Integer.toHexString(status)) ;
        }

        String readingCard ;
        // Read some to make sure they have been added.
        cid[2] = 2 ;
        response = isoReader.sendApdu(0x80, 0xBC, 0x04, 0x00, cid, 0) ;
        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
        	throw new Exception ("ERROR when creating a card: " + Integer.toHexString(status)) ;

        readingCard = ByteArray.bytesToHexString(response, 0, response.length - 2, "") ;
        if (!readingCard.equals("010100020D02000000000000000000000000"))
            throw new Exception ("ERROR when getting a card: " + Integer.toHexString(status)) ;

        // Read some to make sure they have been added.
        cid[2] = 99 ;
        response = isoReader.sendApdu(0x80, 0xBC, 0x04, 0x00, cid, 0) ;
        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
        	throw new Exception ("ERROR when creating a card: " + Integer.toHexString(status)) ;

        readingCard = ByteArray.bytesToHexString(response, 0, response.length - 2, "") ;
        if (!readingCard.equals("010100020D63000000000000000000000000"))
            throw new Exception ("ERROR when getting a card: " + Integer.toHexString(status)) ;

        // Try and add another - should fail
    	cardTlv[2] = 100 ;

    	// Change the first byte of the UI
    	cardTlv[6] = 100 ;

        response = isoReader.sendApdu(0x80, 0xB6, 0x01, 0x00, cardTlv, 0) ;

        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x6983)
            throw new Exception ("ERROR when creating a card: " + Integer.toHexString(status)) ;

        // Delete one in the middle
        cid[2] = 50 ;
        response = isoReader.sendApdu(0x80, 0xBA, 0x00, 0x00, cid, 0) ;
        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
        	throw new Exception ("ERROR when creating a card: " + Integer.toHexString(status)) ;

        // Delete it again - should fail
        response = isoReader.sendApdu(0x80, 0xBA, 0x00, 0x00, cid, 0) ;
        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x6983)
        	throw new Exception ("ERROR when creating a card: " + Integer.toHexString(status)) ;

        // Try and add another - should work
    	cardTlv[2] = 100 ;

    	// Change the first byte of the UI
    	cardTlv[6] = 100 ;

        response = isoReader.sendApdu(0x80, 0xB6, 0x01, 0x00, cardTlv, 0) ;
        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
            throw new Exception ("ERROR when creating a card: " + Integer.toHexString(status)) ;

        // Read some to make sure they have been added.
        cid[2] = 100 ;
        response = isoReader.sendApdu(0x80, 0xBC, 0x04, 0x00, cid, 0) ;
        status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x9000)
        	throw new Exception ("ERROR when creating a card: " + Integer.toHexString(status)) ;

        readingCard = ByteArray.bytesToHexString(response, 0, response.length - 2, "") ;
        if (!readingCard.equals("010100020D64000000000000000000000000"))
            throw new Exception ("ERROR when getting a card: " + Integer.toHexString(status)) ;

    }

}
