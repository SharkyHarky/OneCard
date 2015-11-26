package com.radiius.jacket.scripts;

import java.util.Arrays;

import com.helixion.lok.logger.LogLineType;
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
public class Create_Card_Enc_Error extends JacketTest {

    public Create_Card_Enc_Error(ScriptManager scriptmanager) {
        super(scriptmanager);
        scriptName              = "Create Card - error";
        scriptDescription       = "Verify that an attempt to load the PAN in plaintext generates an error.";
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

        offset = TLVBuilder.putByteTLV(STATE,     (byte)1,  commandData, offset) ;
        offset = TLVBuilder.putTLV(    PAN,       pan,      commandData, offset) ;
        offset = TLVBuilder.putTLV(    UI_STRING, uiString, commandData, offset) ;
        offset = TLVBuilder.putByteTLV(CATEGORY,  (byte)2,  commandData, offset) ;
        offset = TLVBuilder.putByteTLV(PURPOSE,   (byte)3,  commandData, offset) ;
        offset = TLVBuilder.putByteTLV(IMAGE,     (byte)4,  commandData, offset) ;

        // Stick in the length.
        commandData[3] = (byte)(offset - 4) ;

        String loadingCard = ByteArray.bytesToHexString(commandData, 0, offset, "") ;

        byte [] cardTlv = new byte [offset] ;
        System.arraycopy(commandData, 0, cardTlv, 0, cardTlv.length) ;

        // Select the card applet.
        byte [] response = isoReader.sendApdu(0x00, 0xA4, 0x04, 0x00, ByteArray.hexStrToBytes(INSTANCE_AID), 0) ;

        // Issue the create a payment card APDU.
        response = isoReader.sendApdu(0x80, 0xB6, 0x01, 0x00, cardTlv, 0) ;

        int status = ByteArray.getShortBE(response, response.length - 2) ;
        if (status != 0x6985)
        {
            log(LogLineType.RESULT, "ERROR Expected  an exception: " + Integer.toHexString(status)) ;
            throw new Exception ("ERROR Expected  an exception: " + Integer.toHexString(status)) ;
        }
    }

}
