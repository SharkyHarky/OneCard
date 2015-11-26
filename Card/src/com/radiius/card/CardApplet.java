/**
 *
 */
package com.radiius.card;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

/**
 * @author steve.harkins
 *
 */
public class CardApplet extends Applet implements AppletEvent {

	/*
	 * Applet version string.
	 */
    private final static byte []  VERSION                 = {'R','a','d','i','i','u','s',' ','C','a','r','d',' ','A','p','p','l','e','t',' ','0','.','1'};

    /*
     * Applet states.
     */
    private final static byte  APPLET_PERSONALIZED        = (byte)0x0F;

    /*
	 * The class for proprietary APDUs.
	 */
    private final static byte  CLA_PROPRIETARY            = (byte)0x80;

	/*
	 * The GP defined select APDU.
	 */
    private final static short CLA_INS_SELECT             = (short)0x00A4;

	/*
	 * Constants to define the GP defines APDUs to establiish a secure channel for the scripts.
	 */
    private final static short CLA_INS_INITIALISE_UPDATE  = (short)0x8050;
    private final static short CLA_INS_EXTERNAL_AUTH      = (short)0x8082;

    /*
     * Radiius specific APDUs that can only be issued from a script.
     */
    private final static short CLA_INS_PUT_DATA           = (short)0x80DA;

    /*
     * Radiius specific APDUs required during the operational phase.
     */
    private final static short CLA_INS_GET_DATA           = (short)0x80CA;
    private final static short CLA_INS_VALIDATE           = (short)0x80C0;

    /*
     * Radiius specific APDUs required during the operational phase.
     */
    private final static short TAG_CARD_HASH              = (short)0x0001;
    private final static short TAG_SLEEVE_HASH            = (short)0x0002;
    private final static short TAG_AES_MKEY               = (short)0x0004;
    private final static short TAG_VERSION                = (short)0x4000;

    private final static short ALL_FIELDS_PERSOED         = (short)0x0007;

    private final static short NUM_TRANSIENT_STATES       = (short)0x01;
    private final static byte  CARD_AUTH_STATUS           = (byte)0x00;

    // Allocate the transient flags.
    private static boolean[] transientStatus ;

    private static AESKey    validationAesKey ;
    private static Cipher    validationCipher;

    private static byte[]    tmpBuffer ;

    // These personalisation items will be allocated by the PUT DATA.
    private static short     persoFlags = 0 ;
    private static byte[]    sleeveHash ;
    private static byte[]    cardHash ;
    private static byte[]    aesMkey ;

    // Secure Channel Support
    private SecureChannel    mySecureChannel;

	/**
	 * This is the main constructor for the applet, it:
	 * <p>
	 * <ul>
	 * <li> Initialises any variables.
	 * <li> Allocates space to store the card data and initialises it.
	 * <li> Allocates any transient memory require by the applet.
	 * <li> Registers with the framework.
	 * </ul>
	 *
	 * @param buffer the installation buffer.
	 * @param offset an offset into the buffer for the applet specific install parameters
	 * @param length length of the applet specific install parameters
	 */
	private CardApplet(byte[] buffer, short offset, byte length) {

		persoFlags    = 0 ;

    	// Define storage for the transient states (pairing status with handset and card)
        transientStatus    = JCSystem.makeTransientBooleanArray(NUM_TRANSIENT_STATES, JCSystem.CLEAR_ON_RESET);

    	// Initialise a key to be used when validating the card.
        validationAesKey   = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_256, false);
        validationCipher   = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

    	// Allocate temporary buffer that will be cleared on reset.
        tmpBuffer          = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_RESET);

        // Register with the environment.
        this.register(buffer, (short)(offset + 1), buffer[offset]);
	}

	/**
	 * The install method is invoked when the Global Platform framework receives the INSTALL
	 * for INSTALL APDU.
	 * <p>
	 * This allows the applet to be initialised and registered with the platform.
	 *
	 * @param bArray the installation buffer.
	 * @param bOffset an offset into the buffer for the applet specific install parameters
	 * @param bLength length of the applet specific install parameters
	 *
	 * @throws ISOException
	 */
	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
        new CardApplet(bArray, bOffset, bLength);
	}


	/**
	 * Uninstall any bits and pieces.
	 */
	public void uninstall() {
		if (validationAesKey != null)
			validationAesKey.clearKey() ;

		validationAesKey = null ;
		validationCipher = null ;
	}

	/* (non-Javadoc)
     * @see javacard.framework.Applet#select()
     */
    public boolean select()
    {
    	// Get a reference to the secure channel should the applet need it.
        mySecureChannel = GPSystem.getSecureChannel();

        return super.select();
    }

    /* (non-Javadoc)
     * @see javacard.framework.Applet#deselect()
     */
    public void deselect()
    {
    	// Reset the secure channel.
        mySecureChannel.resetSecurity();
    }

    /* (non-Javadoc)
	 * @see javacard.framework.Applet#process(javacard.framework.APDU)
	 */
	public void process(APDU apdu) throws ISOException {

		// Extract the APDU buffer.
        byte[] apduBuffer = apdu.getBuffer();

        // Pull out the class and instruction bytes.
        short cla_ins = (short)(Util.getShort(apduBuffer, ISO7816.OFFSET_CLA) & (short)0xF0FF);
        short cla     = (byte)(apduBuffer[ISO7816.OFFSET_CLA] & 0xF0);

        if (cla_ins == CLA_INS_SELECT)
        {
            // Check that the select command is actually selecting this applet.
            if (!selectingApplet())
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);

            return ;
        }

        // Check the class byte - for Radiius it should always be 0x80.
        if (CLA_PROPRIETARY != cla)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        // Determines the length of the response.
        short dataToSend = 0 ;

        // For each valid instruction call the appropriate method.
        switch (cla_ins)
        {

        // The global platform commands will be handled by the associated security domain.
        case	CLA_INS_INITIALISE_UPDATE:
        case	CLA_INS_EXTERNAL_AUTH:
        	dataToSend = mySecureChannel.processSecurity(apdu);
        	break ;

        /*
         * The PUT DATA and UNBLOCK PIN must be sent in a secured script from either
         * the perso tool or an OTA script.
         *
         * As such they must be preceded by an Initialise Update and an External authenticate.
         */
        case	CLA_INS_PUT_DATA:
        	putData(apdu) ;
        	break ;

        /*
         * The remaining commands will be issued by the MCU after selecting the applet.
         */
        case	CLA_INS_GET_DATA:
        	dataToSend = getData(apdu) ;
        	break ;
        case	CLA_INS_VALIDATE:
        	dataToSend = validate(apdu) ;
        	break ;

        // If the cla ins combination was not recognised the report an error.
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);

        }

        if (dataToSend > (short)0)
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataToSend);
	}

	/**
	 * This handles the PU DATA APDU issued as part of the personalisation script.
	 * <p>
	 * <b>Note:</> That this can only be issued over a secure channel.
	 *
	 * @param apdu a reference to the APDU.
	 */
	private void putData(APDU apdu) {

        byte[] apduBuffer = apdu.getBuffer();

        // Extract the tag of the data item to be personalised - mask off the last put bit.
        short tag    = (short) (Util.getShort(apduBuffer, ISO7816.OFFSET_P1) & 0x0FFF);
        byte  p1     = (byte)(apduBuffer[ISO7816.OFFSET_P1] & 0x80);

        // Remove the security from the APDU exposing the validates plaintext payload.
        short length = mySecureChannel.unwrap(apduBuffer, (short)0, (short)(apdu.setIncomingAndReceive() + 5));

        // Only allow when in INSTAALLED state - not allowed after perso complete.
        if (GPSystem.getCardContentState() != GPSystem.APPLICATION_SELECTABLE)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        length = (short)((short)apduBuffer[ISO7816.OFFSET_LC] & 0xFF ) ;

        switch (tag)
        {
	        case TAG_CARD_HASH:
	        	cardHash = new byte[length] ;
	        	Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, cardHash, (short)0, length) ;
                break;

	        case TAG_SLEEVE_HASH:
	        	sleeveHash = new byte[length] ;
	        	Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, sleeveHash, (short)0, length) ;
                break;

	        case TAG_AES_MKEY:
	        	aesMkey = new byte[length] ;
	        	Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, aesMkey, (short)0, (short)length) ;
                break;

            // If the tag is not found reply with an invalid status.
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Mark the field as personalised.
        persoFlags |= tag ;

        // If this is the last put data of personalisation, verify that all fields have been personalised.
        if ((p1 & 0x80) != 0) {
    		if (persoFlags != ALL_FIELDS_PERSOED)
    			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

            GPSystem.setCardContentState(APPLET_PERSONALIZED);
        }
	}

	private short getData(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        // Extract the tag of the data item to be personalised.
        short tag    = (short) (Util.getShort(apduBuffer, ISO7816.OFFSET_P1) & 0x7FFF);

        // Only allow when in INSTAALLED state - not allowed after perso complete.
        if (tag != TAG_VERSION) {

        	if (GPSystem.getCardContentState() != APPLET_PERSONALIZED)
        		ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }

    	short dataToSend = Util.setShort(apduBuffer, ISO7816.OFFSET_CDATA, tag) ;
        switch (tag)
        {
	        case TAG_VERSION:
	            apduBuffer[dataToSend++] = (byte)VERSION.length ;
	        	dataToSend  = Util.arrayCopyNonAtomic(VERSION, (short)0, apduBuffer, dataToSend, (short)VERSION.length);
                break;

            // If the tag is not found reply with an invalid status.
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
		return dataToSend ;
	}

	private short validate(APDU apdu) {
		// Retrieve a reference to the APDU buffer.
        byte[] apduBuffer = apdu.getBuffer();

        if ((apduBuffer[ISO7816.OFFSET_P2] < 0) || (apduBuffer[ISO7816.OFFSET_P2] > 2))
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        if (apduBuffer[ISO7816.OFFSET_P1] != 1)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        short length = (short) ((short)apduBuffer[ISO7816.OFFSET_LC] & 0xFF) ;

        if (length < 2)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // Extract the random and build the session key.
        setSessionKey(Util.getShort(apduBuffer, ISO7816.OFFSET_CDATA)) ;

        // Adjust the length to account for the random.
        length -= 2 ;

        // Decrypt the supplied jacket hash.
        validationCipher.init(validationAesKey, Cipher.MODE_DECRYPT);
        validationCipher.doFinal(apduBuffer, (short)(ISO7816.OFFSET_CDATA + 2), length, apduBuffer, (short)(ISO7816.OFFSET_CDATA + 2));

        short rspLength = 0 ;

        // Verify that the card hash matches.
    	if (Util.arrayCompare(apduBuffer, (short)(ISO7816.OFFSET_CDATA + 2),                   cardHash,   (short)0, (short)cardHash.length) != 0)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

    	// Verify that the jacket hash matches.
    	if (Util.arrayCompare(apduBuffer, (short)(ISO7816.OFFSET_CDATA + 2 + cardHash.length), sleeveHash, (short)0, (short)sleeveHash.length) != 0)
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

    	rspLength = Util.arrayCopyNonAtomic(cardHash,   (short)0, apduBuffer,         ISO7816.OFFSET_CDATA,                    (short)cardHash.length) ;
    	rspLength = Util.arrayCopyNonAtomic(sleeveHash, (short)0, apduBuffer, (short)(ISO7816.OFFSET_CDATA + cardHash.length), (short)cardHash.length) ;
    	transientStatus[CARD_AUTH_STATUS] = true ;

        // If there is data to return - pad and encrypt it.
        if (rspLength > ISO7816.OFFSET_CDATA)
        {
        	rspLength -= ISO7816.OFFSET_CDATA ;
	    	// Encrypt using the session key.
	        validationCipher.init(validationAesKey, Cipher.MODE_ENCRYPT);
	        validationCipher.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, (short)rspLength, apduBuffer, ISO7816.OFFSET_CDATA);
        }
		return rspLength ;
	}

	private void setSessionKey(short rnd) {

		// Initialise the key derivation data to all 0.
		Util.arrayFillNonAtomic(tmpBuffer, (short)0, (short) aesMkey.length, (byte)0) ;

		// Write the RND at the start of the buffer.
		Util.setShort(tmpBuffer, (short)0, rnd) ;

		// Write the RND at the start of the buffer.
		Util.setShort(tmpBuffer, (short)(aesMkey.length >> 1), (short)~rnd) ;

		// Encrypt using the master key.
        validationAesKey.setKey(aesMkey, (short)0);
        validationCipher.init(validationAesKey, Cipher.MODE_ENCRYPT);
        validationCipher.doFinal(tmpBuffer, (short)0, (short)aesMkey.length, tmpBuffer, (short)aesMkey.length);

		// Use the resulting encrypted data as the session key.
        validationAesKey.setKey(tmpBuffer, (short)aesMkey.length);
	}

	public static boolean isPaiired()
	{
		return transientStatus[CARD_AUTH_STATUS];
	}

}
