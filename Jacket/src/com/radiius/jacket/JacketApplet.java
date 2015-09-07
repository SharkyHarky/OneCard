/**
 * 
 */
package com.radiius.jacket;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateCrtKey;
import javacardx.crypto.Cipher;

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

/**
 * @author steve.harkins
 *
 */
public class JacketApplet extends Applet {

	/*
	 * Applet version string.
	 */
    private final static byte []  VERSION                 = {'R','a','d','i','i','u','s',' ','S','l','e','e','v','e',' ','A','p','p','l','e','t',' ','0','.','1'};

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
    private final static short CLA_INS_UNBLOCK_PIN        = (short)0x80B2;

    /*
     * Radiius specific APDUs required during the operational phase.
     */
    private final static short CLA_INS_GET_DATA           = (short)0x80CA;
    private final static short CLA_INS_VERIFY_PIN         = (short)0x80B0;
    private final static short CLA_INS_CHANGE_PIN         = (short)0x80B4;
    private final static short CLA_INS_CREATE_CARD        = (short)0x80B6;
    private final static short CLA_INS_UPDATE_CARD        = (short)0x80B8;
    private final static short CLA_INS_DELETE_CARD        = (short)0x80BA;
    private final static short CLA_INS_GET_CARD           = (short)0x80BC;
    private final static short CLA_INS_VALIDATE           = (short)0x80C0;
    private final static short CLA_INS_PAIR               = (short)0x80C2;

    /*
     * Radiius specific APDUs required during the operational phase.
     */
    private final static short TAG_SLEEVE_HASH            = (short)0x0001;
    private final static short TAG_CARD_HASH              = (short)0x0002;
    private final static short TAG_AES_MKEY               = (short)0x0004;
    private final static short TAG_PIN                    = (short)0x0008;
    private final static short TAG_RSA_Q_1_MOD_P          = (short)0x0010;
    private final static short TAG_RSA_D_MOD_Q_1          = (short)0x0020;
    private final static short TAG_RSA_D_MOD_P_1          = (short)0x0040;
    private final static short TAG_RSA_PRIME_Q            = (short)0x0080;
    private final static short TAG_RSA_PRIME_P            = (short)0x0100;
    private final static short TAG_RSA_PUB_EXP            = (short)0x0200;
    private final static short TAG_RSA_PUB_MOD            = (short)0x0400;
    private final static short TAG_VERSION                = (short)0x1042;

    private final static short ALL_FIELDS_PERSOED         = (short)0x01FF;

    private final static byte  MAX_PIN_LENGTH             = (byte)0x08;

    private final static short NUM_TRANSIENT_STATES       = (short)0x02;
    private final static byte  PAIRING_STATUS             = (byte)0x00;
    private final static byte  CARD_AUTH_STATUS           = (byte)0x01;

    // Allocate the transient flags.
    private static boolean[] transientStatus ;

    private static AESKey    validationAesKey ;
    private static Cipher    validationCipher;

    private static RSAPrivateCrtKey sleeveRSAPrivateCrtKey;
    private static Cipher           rsaCipher;

    private static byte[]    tmpBuffer ;

    // These personalisation items will be allocated by the PUT DATA. 
    private static short     persoFlags = 0 ;
    private static byte[]    sleeveHash ;
    private static byte[]    cardHash ;
    private static byte[]    aesMkey ;
    private static byte[]    pubKeyExp ;
    private static byte[]    pubKeyMod ;

    private static OwnerPIN  sleevePin ;
    
    // Secure Channel Support
    private SecureChannel mySecureChannel;

    private static byte[]    handsetFingerprint ;
    
    CardStore cardStore = null ;

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
	private JacketApplet(byte[] buffer, short offset, byte length) {
		
		persoFlags    = 0 ;

		cardStore = new CardStore() ;
		
        // *** All transient memory should be allocated within this block ****
        if (transientStatus == null)
        {
        	// Define storage for the transient states (pairing status with handset and card)
            transientStatus = JCSystem.makeTransientBooleanArray(NUM_TRANSIENT_STATES, JCSystem.CLEAR_ON_RESET);

        	// Initialise a key to be used when validating the card.
            validationAesKey   = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_256, false);

            validationCipher   = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

            // Initialise a key to be used when pairing with the handset.
            sleeveRSAPrivateCrtKey = (RSAPrivateCrtKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, KeyBuilder.LENGTH_RSA_1984, false);

        	// Allocate temporary buffer that will be cleared on reset. 
            tmpBuffer = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_RESET);
            
            sleevePin = new OwnerPIN((byte)3, MAX_PIN_LENGTH);
        }

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
        new JacketApplet(bArray, bOffset, bLength);
	}

    /* (non-Javadoc)
     * @see javacard.framework.Applet#select()
     */
	// Invoked by the framework when the applet is selected.
    public boolean select()
    {
    	// Get a reference to the secure channel should the applet need it.
        mySecureChannel = GPSystem.getSecureChannel();

        return super.select();
    }

    /* (non-Javadoc)
     * @see javacard.framework.Applet#deselect()
     */
	// Invoked by the framework when the applet is selected.
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
        short cla_ins = (short)(Util.getShort(apduBuffer, ISO7816.OFFSET_CLA) & (short)0xFCFF);

        if (cla_ins == CLA_INS_SELECT)
        {
            // Check that the select command is actually selecting this applet.
            if (!selectingApplet())
                ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
            
            return ;
        }

        // Check the class byte - for Radiius it should always be 0x80.
        if (CLA_PROPRIETARY != (byte)(apduBuffer[ISO7816.OFFSET_CLA] & (byte)0xFC))
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
        case	CLA_INS_UNBLOCK_PIN:
        	unblockPin(apdu) ;
        	break ;

        /*
         * The remaining commands will be issued by the MCU after selecting the applet.
         */
        case	CLA_INS_GET_DATA:
        	dataToSend = getData(apdu) ;
        	break ;
        case	CLA_INS_VERIFY_PIN:
        	verifyPin(apdu) ;
        	break ;
        case	CLA_INS_CHANGE_PIN:
        	changePin(apdu) ;
        	break ;
        case	CLA_INS_CREATE_CARD:
        	createCard(apdu) ;
        	break ;
        case	CLA_INS_UPDATE_CARD:
        	updateCard(apdu) ;
        	break ;
        case	CLA_INS_DELETE_CARD:
            cardStore.deleteCard(apdu.getBuffer()) ;
        	break ;
        case	CLA_INS_GET_CARD:
        	dataToSend = getCard(apdu) ;
        	break ;
        case	CLA_INS_VALIDATE:
        	dataToSend = validate(apdu) ;
        	break ;
        case	CLA_INS_PAIR:
        	pair(apdu) ;
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
        short tag    = (short) (Util.getShort(apduBuffer, ISO7816.OFFSET_P1) & 0x7FFF);

        // Remove the security from the APDU exposing the validates plaintext payload.
        short length = mySecureChannel.unwrap(apduBuffer, (short)0, (short)(apdu.setIncomingAndReceive() + 5));

        // Only allow when in INSTAALLED state - not allowed after perso complete.
        if (GPSystem.getCardContentState() == GPSystem.APPLICATION_SELECTABLE)
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);

        switch (tag)
        {
	        case TAG_SLEEVE_HASH:
	        	sleeveHash = new byte[length] ;
	        	Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, sleeveHash, (short)0, length) ;
                break;
                
	        case TAG_CARD_HASH:
	        	cardHash = new byte[length] ;
	        	Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, cardHash, (short)0, length) ;
                break;
                
	        case TAG_AES_MKEY:
	        	aesMkey = new byte[length] ;
	        	Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, aesMkey, (short)0, length) ;
                break;
                
	        case TAG_PIN:
	        	sleevePin.update(apduBuffer, ISO7816.OFFSET_CDATA, (byte) length) ;
                break;
                
            case TAG_RSA_Q_1_MOD_P: // q-1 mod p
                sleeveRSAPrivateCrtKey.setPQ(apduBuffer,  ISO7816.OFFSET_CDATA, length);
                break;

            case TAG_RSA_D_MOD_Q_1: // d mod (q - 1)
            	sleeveRSAPrivateCrtKey.setDQ1(apduBuffer, ISO7816.OFFSET_CDATA, length);
                break;

            case TAG_RSA_D_MOD_P_1: // d mod (p - 1)
            	sleeveRSAPrivateCrtKey.setDP1(apduBuffer, ISO7816.OFFSET_CDATA, length);
                break;

            case TAG_RSA_PRIME_Q: // prime factor q
            	sleeveRSAPrivateCrtKey.setQ(apduBuffer,   ISO7816.OFFSET_CDATA, length);
                break;

            case TAG_RSA_PRIME_P: // prime factor p
            	sleeveRSAPrivateCrtKey.setP(apduBuffer,   ISO7816.OFFSET_CDATA, length);
               break;

            case TAG_RSA_PUB_EXP:
	        	pubKeyExp = new byte[length] ;
	        	Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, pubKeyExp, (short)0, length) ;
                break;
                
	        case TAG_RSA_PUB_MOD:
	        	pubKeyMod = new byte[length] ;
	        	Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, pubKeyMod, (short)0, length) ;
                break;

            // If the tag is not found reply with an invalid status.
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        
        // Mark the field as personalised.
        persoFlags |= tag ;
        
        // If this is the last put data of personalisation, verify that all fields have been personalised.
        if ((((byte)(apduBuffer[ISO7816.OFFSET_P1] & 0x80) != 0)) &&  ((persoFlags & ALL_FIELDS_PERSOED) != ALL_FIELDS_PERSOED)) 
        	ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        // Initialise the RSA cipher.
        rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);

        GPSystem.setCardContentState(APPLET_PERSONALIZED);

	}

	private void unblockPin(APDU apdu) {

        byte[] apduBuffer = apdu.getBuffer();

        // Remove the security from the APDU exposing the validates plaintext payload.
        short length = mySecureChannel.unwrap(apduBuffer, (short)0, (short)(apdu.setIncomingAndReceive() + 5));

        // Only allow when in INSTAALLED state - not allowed after perso complete.
        if (GPSystem.getCardContentState() == GPSystem.APPLICATION_SELECTABLE)
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

    	length = (short) ((short)apduBuffer[ISO7816.OFFSET_CDATA] & 0xFF) ;
    	sleevePin.update(apduBuffer, (short)(ISO7816.OFFSET_CDATA + 1), (byte)length);
    	sleevePin.resetAndUnblock();
	}

	private short getData(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        // Extract the tag of the data item to be personalised.
        short tag    = (short) (Util.getShort(apduBuffer, ISO7816.OFFSET_P1) & 0x7FFF);

        // Only allow when in INSTAALLED state - not allowed after perso complete.
        if ((tag != TAG_VERSION) && (GPSystem.getCardContentState() == APPLET_PERSONALIZED))
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

    	short dataToSend = Util.setShort(apduBuffer, (short)0, tag) ;
        switch (tag)
        {
	        case TAG_VERSION:
	            apduBuffer[dataToSend++] = (byte)VERSION.length ;
	        	dataToSend  = Util.arrayCopyNonAtomic(VERSION, (short)0, apduBuffer, dataToSend, (short)VERSION.length);
                break;
                
	        case TAG_RSA_PUB_EXP:
	            apduBuffer[dataToSend++] = (byte)pubKeyExp.length ;
	        	dataToSend  = Util.arrayCopyNonAtomic(pubKeyExp, (short)0, apduBuffer, dataToSend, (short)pubKeyExp.length);
                break;
                
	        case TAG_RSA_PUB_MOD:
	            apduBuffer[dataToSend++] = (byte)pubKeyMod.length ;
	        	dataToSend  = Util.arrayCopyNonAtomic(pubKeyMod, (short)0, apduBuffer, dataToSend, (short)pubKeyMod.length);
                break;
                
            // If the tag is not found reply with an invalid status.
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
		return dataToSend ;
	}

	private void verifyPin(APDU apdu) {
		
		// Retrieve a reference to the APDU buffer.
        byte[] apduBuffer = apdu.getBuffer();

        // If there are no retries available - throw an error.
        if (sleevePin.getTriesRemaining() == (byte)0)
            ISOException.throwIt(ISO7816.SW_FILE_INVALID);

        // Determine the length of the command data.
        short length = (short) ((short)apduBuffer[ISO7816.OFFSET_LC] & 0xFF) ;
        
        // Decrypt using the sleeve private key.
        rsaCipher.init(sleeveRSAPrivateCrtKey, Cipher.MODE_DECRYPT);
        rsaCipher.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, length, apduBuffer, length);

        
        short offset = ISO7816.OFFSET_CDATA ;

        // Get the length of the handset fingerprint.
        length = (short) ((short)apduBuffer[offset++] & 0xFF) ;

        // If the fingerprint has not been saved yet - save it.
        if (null == handsetFingerprint)
        {
        	handsetFingerprint = new byte[length] ;
        	Util.arrayCopyNonAtomic(apduBuffer, offset, handsetFingerprint, (short)0, length) ;
        }
        else
        {
        	if (length != (short)handsetFingerprint.length)
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

        	if (Util.arrayCopyNonAtomic(apduBuffer, offset, handsetFingerprint, (short)0, length) != 0)
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        
        // Move on to the PIN.
        offset += length ;
        
        // Compare the received PIN with the reference one.
        length = (short) ((short)apduBuffer[offset++] & 0xFF) ;
        if (!sleevePin.check(apduBuffer, offset, (byte)length))
        {
        	// Set the return status to indicate the number of retries.
            byte retries = sleevePin.getTriesRemaining();

            ISOException.throwIt((short)(0x63C0 + retries));
        }
        else
        	transientStatus[PAIRING_STATUS] = true ;

	}
	
	private void changePin(APDU apdu) {
		// Retrieve a reference to the APDU buffer.
        byte[] apduBuffer = apdu.getBuffer();

        // If there are no retries available - throw an error.
        if (sleevePin.getTriesRemaining() == (byte)0)
            ISOException.throwIt(ISO7816.SW_FILE_INVALID);

        // Determine the length of the command data.
        short length = (short) ((short)apduBuffer[ISO7816.OFFSET_LC] & 0xFF) ;
        
        // Decrypt using the sleeve private key.
        rsaCipher.init(sleeveRSAPrivateCrtKey, Cipher.MODE_DECRYPT);
        rsaCipher.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, length, apduBuffer, ISO7816.OFFSET_CDATA);

        // Compare the handset fingerprint with the paired one.
        short offset = ISO7816.OFFSET_CDATA ;
        length = (short) ((short)apduBuffer[offset++] & 0xFF) ;
        
    	if (length != (short)handsetFingerprint.length)
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

    	if (Util.arrayCopyNonAtomic(apduBuffer, offset, handsetFingerprint, (short)0, length) != 0)
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

        // Move on to the existing PIN.
        offset += length ;
        
        if (!sleevePin.check(apduBuffer, offset, (byte) length))
        {
        	// Set the return status to indicate the number of retries.
            byte retries = sleevePin.getTriesRemaining();

            ISOException.throwIt((short)(0x63C0 + retries));
        }
        else
        {
            // Move on to the new PIN.
            offset += length ;

            length = (short) ((short)apduBuffer[offset++] & 0xFF) ;
        	sleevePin.update(apduBuffer, offset, (byte)length);
        	sleevePin.resetAndUnblock();
        }
	}
	
	private void createCard(APDU apdu) {
		boolean encrypted = false ;
		
		// Retrieve a reference to the APDU buffer.
        byte[] apduBuffer = apdu.getBuffer();

        // Determine the length of the command data.
        short length = (short) ((short)apduBuffer[ISO7816.OFFSET_LC] & 0xFF) ;
        
        // If the packet contains sensitive information - decrypt is using the private key.
        if (apduBuffer[ISO7816.OFFSET_P2] == 1) {
        	encrypted = true ;
        	
		    // Decrypt using the sleeve private key.
		    rsaCipher.init(sleeveRSAPrivateCrtKey, Cipher.MODE_DECRYPT);
		    rsaCipher.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, length, apduBuffer, ISO7816.OFFSET_CDATA);
        }

        cardStore.createCard(apduBuffer, encrypted) ;
        
	}
	
	private void updateCard(APDU apdu) {
		boolean encrypted = false ;

		// Retrieve a reference to the APDU buffer.
        byte[] apduBuffer = apdu.getBuffer();

        // Determine the length of the command data.
        short length = (short) ((short)apduBuffer[ISO7816.OFFSET_LC] & 0xFF) ;
        
        // If the packet contains sensitive information - decrypt is using the private key.
        if (apduBuffer[ISO7816.OFFSET_P2] == 1) {
        	encrypted = true ;

        	// Decrypt using the sleeve private key.
		    rsaCipher.init(sleeveRSAPrivateCrtKey, Cipher.MODE_DECRYPT);
		    rsaCipher.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, length, apduBuffer, ISO7816.OFFSET_CDATA);
        }

        cardStore.updateCard(apduBuffer, encrypted) ;
        
	}
	
	private short getCard(APDU apdu) {
		boolean encrypted = false ;
		
		// Retrieve a reference to the APDU buffer.
        byte[] apduBuffer = apdu.getBuffer();

        short p1 = (short) ((short)apduBuffer[ISO7816.OFFSET_P1] & 0xFF) ;

        // Determine the length of the command data.
        short length = (short) ((short)apduBuffer[ISO7816.OFFSET_LC] & 0xFF) ;
        
        // If the packet contains sensitive information - decrypt is using the private key.
        if (apduBuffer[ISO7816.OFFSET_P2] == 1) {
        	encrypted = true ;
        	apduBuffer = apdu.getBuffer();
        	
		    // Decrypt using the sleeve private key.
		    rsaCipher.init(sleeveRSAPrivateCrtKey, Cipher.MODE_DECRYPT);
		    rsaCipher.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, length, apduBuffer, ISO7816.OFFSET_CDATA);

            // Compare the handset fingerprint with the paired one.
		    short offset = (short)(ISO7816.OFFSET_CDATA + 3) ;
            length = (short) ((short)apduBuffer[offset++] & 0xFF) ;
            
        	if (length != (short)handsetFingerprint.length)
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

        	if (Util.arrayCopyNonAtomic(apduBuffer, offset, handsetFingerprint, (short)0, length) != 0)
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

            // Move on to the PIN.
            offset += length ;

            // Get the length of the PIN.
            length = (short) ((short)apduBuffer[offset++] & 0xFF) ;

            // Compare the PIN with the reference one.
            if (!sleevePin.check(apduBuffer, offset, (byte) length))
            {
            	// Set the return status to indicate the number of retries.
                byte retries = sleevePin.getTriesRemaining();

                ISOException.throwIt((short)(0x63C0 + retries));
            }
        }
        else
        {
        	// If the data is not encrypted the if P1 indicates that it is the sensitive data throw an error.
        	if (p1 == 3) 
                ISOException.throwIt(ISO7816.SW_FILE_INVALID);
        }

        // Handle the gget card.
        length = cardStore.getCard(apduBuffer) ;

        // If encrypted - do it.
        if (encrypted) {
        	// Encrypt using the session key.
	        validationCipher.init(validationAesKey, Cipher.MODE_ENCRYPT);
	        length = validationCipher.doFinal(apduBuffer, (short)0, length, apduBuffer, (short)0);
        }

        return length ;
	}
	
	private short validate(APDU apdu) {
		// Retrieve a reference to the APDU buffer.
        byte[] apduBuffer = apdu.getBuffer();

        if ((apduBuffer[ISO7816.OFFSET_P2] < 0) || (apduBuffer[ISO7816.OFFSET_P2] > 2))
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        
        short p1     = (short) ((short)apduBuffer[ISO7816.OFFSET_P1] & 0xFF) ;
        short length = (short) ((short)apduBuffer[ISO7816.OFFSET_LC] & 0xFF) ;
        
        if (length < 2)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        // Extract the random and build the session key.
        setSessionKey(Util.getShort(apduBuffer, ISO7816.OFFSET_CDATA)) ;

        // If there is a hash included in the command data - decrypt it. 
        if (p1 != 0) {
	    	// Encrypt using the session key.
	        validationCipher.init(validationAesKey, Cipher.MODE_DECRYPT);
	        validationCipher.doFinal(apduBuffer, (short)(ISO7816.OFFSET_CDATA + 2), length, apduBuffer, (short)(ISO7816.OFFSET_CDATA + 2));
        }

        length = 0 ;
        switch (apduBuffer[ISO7816.OFFSET_P1]) {
	        case 0:
	        	length = Util.arrayCopyNonAtomic(sleeveHash, (short)0, apduBuffer, (short)0, (short)sleeveHash.length) ;
	        	break ;
	
	        case 1:
	        	if (Util.arrayCompare(apduBuffer, (short)(ISO7816.OFFSET_CDATA + 2), sleeveHash, (short)0, (short)sleeveHash.length) != 0)
	                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
	        	length = Util.arrayCopyNonAtomic(cardHash, (short)0, apduBuffer, (short)0, (short)cardHash.length) ;
	        	break ;
	
	        case 2:
	        	if (Util.arrayCompare(apduBuffer, (short)(ISO7816.OFFSET_CDATA + 2), cardHash, (short)0, (short)cardHash.length) != 0)
	                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
	        	transientStatus[CARD_AUTH_STATUS] = true ;
	        	break ;
	        	
        	default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // If there is data to return - pad and encrypt it.
        if (length > 0)
        {
        	// Pad the data with 0's
	    	while ((length & 0xF) != 0)
	    		apduBuffer[length++] = 0 ;
	    	
	    	// Encrypt using the session key.
	        validationCipher.init(validationAesKey, Cipher.MODE_ENCRYPT);
	        validationCipher.doFinal(apduBuffer, (short)0, length, apduBuffer, (short)0);
        }        
		return length ;
	}

	private void pair(APDU apdu) {
		
		// Retrieve a reference to the APDU buffer.
        byte[] apduBuffer = apdu.getBuffer();

        // Determine the length of the command data.
        short length = (short) ((short)apduBuffer[ISO7816.OFFSET_LC] & 0xFF) ;
        
        // Decrypt using the sleeve private key.
        rsaCipher.init(sleeveRSAPrivateCrtKey, Cipher.MODE_DECRYPT);
        rsaCipher.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, length, apduBuffer, ISO7816.OFFSET_CDATA);

        length = (short) ((short)apduBuffer[ISO7816.OFFSET_CDATA] & 0xFF) ;
        
        // If the fingerprint has not been saved yet - save it.
        if (null == handsetFingerprint)
        {
        	handsetFingerprint = new byte[length] ;
        	Util.arrayCopyNonAtomic(apduBuffer, (short)(ISO7816.OFFSET_CDATA + 1), handsetFingerprint, (short)0, length) ;
        }
        else
        {
        	if (length != (short)handsetFingerprint.length)
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

        	if (Util.arrayCopyNonAtomic(apduBuffer, (short)(ISO7816.OFFSET_CDATA + 1), handsetFingerprint, (short)0, length) != 0)
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        
        // Set the pairing state to true.
    	transientStatus[PAIRING_STATUS] = true ;
	}
	
	private void setSessionKey(short rnd) {
	
		// Initialise the key derivation data to all 0.
		Util.arrayFillNonAtomic(tmpBuffer, (short)0, (short) aesMkey.length, (byte)0) ;
	
		// Write the RND at the start of the buffer.
		Util.setShort(tmpBuffer, (short)0, rnd) ;
		
		// Write the RND at the start of the buffer.
		Util.setShort(tmpBuffer, (short)(aesMkey.length >> 1), (short)~rnd) ;
		
		// Encrypt using the master key.
        validationAesKey.setKey(tmpBuffer, (short)0);
        validationCipher.init(validationAesKey, Cipher.MODE_ENCRYPT);
        validationCipher.doFinal(tmpBuffer, (short)0, (short)aesMkey.length, tmpBuffer, (short)0);

		// Use the resulting encrypted data as the session key.
        validationAesKey.setKey(tmpBuffer, (short)0);
	}

}
