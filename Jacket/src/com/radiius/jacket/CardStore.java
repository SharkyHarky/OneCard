/**
 * 
 */
package com.radiius.jacket;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * @author steve.harkins
 *
 */
public class CardStore {

	/*
	 * Empty card slot - CID = 000;
	 */
    private final static byte []  EMPTY_CARD_ID           = {0, 0, 0};

    /*
     * Card constants.
     * <p>
     * The card content is structured as a CID followed by a series of TLVs.
     * <p>
     * The TLV structure is used for flexibility. 
     */
    private final static byte  MAX_NUMBER_OF_CARDS        = (byte)100 ;
    private final static short SIZE_OF_CARD_DATA_BLOCK    = (short)0x0100;
    private final static short MAX_CARD_SIZE              = (short)(SIZE_OF_CARD_DATA_BLOCK - 4);
    
    private final static byte  TAG_STATE                  = 1 ;
    private final static byte  TAG_UI_STRING              = 2 ;
    private final static byte  TAG_TRACK_1_DATA           = 3 ;
    private final static byte  TAG_TRACK_2_DATA           = 4 ;
    private final static byte  TAG_TRACK_3_DATA           = 5 ;
    private final static byte  TAG_PAYMENT_AID            = 6 ;
    private final static byte  TAG_PAYMENT_DISPLAY_NAME   = 7 ;
    private final static byte  TAG_PAN                    = 8 ;
    private final static byte  TAG_CVV                    = 9 ;
    private final static byte  TAG_EXPIRY_DATE            = 10 ;
    private final static byte  TAG_CATEGORY               = 11 ;
    private final static byte  TAG_PURPOSE                = 12 ;
    private final static byte  TAG_IMAGE                  = 13 ;

	/*
	 * Inactive state TLV.
	 */
    private final static byte     STATE_INACTIVE          = 0 ;
    private final static byte []  INACTIVE_STATE_TLV      = {TAG_STATE, 0, STATE_INACTIVE} ;

    private static short     numberOfCards ;
    private static byte []   cardDatabase ;

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
	CardStore() {
		
		numberOfCards = 0 ;

		// Allocate the space card storage and clear it down.
		cardDatabase = new byte [(short)(MAX_NUMBER_OF_CARDS * SIZE_OF_CARD_DATA_BLOCK)] ;
		Util.arrayFillNonAtomic(cardDatabase, (short)0, (short)cardDatabase.length, (byte)0) ;
		
	}

	void createCard(byte [] apduBuffer, boolean encrypted) {

        // Find the card in question.
        short offset = findCard(apduBuffer, ISO7816.OFFSET_CDATA) ;

        // If the file already exists throw an exception.
        if (offset > 0)
            ISOException.throwIt(ISO7816.SW_FILE_INVALID);

        // Find the first empty card slot.
        short cardOffset = findCard(EMPTY_CARD_ID, (short)0) ;

        // If the card database is full throw an exceeption.
        if (offset == -1)
            ISOException.throwIt(ISO7816.SW_FILE_INVALID);

        // Copy in the CID.
        cardOffset = Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, cardDatabase, cardOffset, (short)0) ;

        // Get the length of the TLVs
        short length = (short) ((short)apduBuffer[(short)(ISO7816.OFFSET_CDATA + 3)] & 0xFF) ;
        
        // Set the length of the card data.
        cardDatabase[cardOffset++] = (byte)length ;
        		
        // Copy in the TLV.
        Util.arrayCopyNonAtomic(apduBuffer, (short)(ISO7816.OFFSET_CDATA + 4), cardDatabase, cardOffset, length) ;

    	// If any of the sensitive data was passed in the clear throw an error.
		if (!encrypted) {
			
	    	if ((findTlv(cardOffset, TAG_PAN) > 0) || (findTlv(cardOffset, TAG_CVV) > 0) || (findTlv(cardOffset, TAG_EXPIRY_DATE) > 0))
	    	{
	            // Delete the card data.
	            Util.arrayFillNonAtomic(cardDatabase, offset, SIZE_OF_CARD_DATA_BLOCK, (byte)0) ;
	            
	            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
	    	}
		}
		
    	// If the state was loaded - make sure it is inactive.
    	cardOffset = findTlv(cardOffset, TAG_STATE) ; 
    	if (cardOffset > 0)
    		cardDatabase[(short)(cardOffset + 2)] = STATE_INACTIVE ;
    	else
    		appendTlv(cardOffset, INACTIVE_STATE_TLV, (short)0, (short)INACTIVE_STATE_TLV.length) ;
	}
	
	void updateCard(byte[] apduBuffer, boolean encrypted) {

        // Find the card in question.
        short cardOffset = findCard(apduBuffer, ISO7816.OFFSET_CDATA) ;


        // If the file already exists throw an exception.
        if (cardOffset < 0)
            ISOException.throwIt(ISO7816.SW_FILE_INVALID);

        /// Move passed the CID.
        short tlvOffset = (short)(ISO7816.OFFSET_CDATA + 3) ;

        // Get the length of the TLVs
        short length = (short) ((short)apduBuffer[tlvOffset] & 0xFF) ;

        // For each TLV in the APDU.
        short existingTlv ;
        short tlvLength ;
        while (tlvOffset < length)
        {
        	existingTlv = findTlv(cardOffset, apduBuffer[tlvOffset]) ;
        	
        	tlvLength = (short) ((short)apduBuffer[(short)(tlvOffset + 1)] & 0xFF) ;
        	// If there is no existing TLV append this one to the list.
        	if (existingTlv < 0)
        	{
        		appendTlv(cardOffset, apduBuffer, tlvOffset, (short)(tlvLength + 2)) ;
        	}
        	else
        	{
        		// Get the existing TLV length.
            	short existingLength = (short) ((short)cardDatabase[(short)(existingTlv + 1)] & 0xFF) ;
            	
            	// If they are the same length simply overwrite the value.
            	if (existingLength == tlvLength)
            	{
            		// Over write the value with the new one.
            		Util.arrayCopyNonAtomic(apduBuffer, (short)(tlvOffset + 2), cardDatabase, (short)(existingTlv + 2), tlvLength);
            	}
            	else
            	{
            		// Delete the old one.
            		deleteTlv(cardOffset, existingTlv) ;
            		
            		// Append the new one.
            		appendTlv(cardOffset, apduBuffer, tlvOffset, (short)(tlvLength + 2)) ;
            	}
        		
        	}
        	
        	// Move to the next TLV.
        	tlvOffset +=  (short)(tlvLength + 2) ;
        }
	}
	
	void deleteCard(byte[] apduBuffer) {

        // Find the card in question.
        short offset = findCard(apduBuffer, ISO7816.OFFSET_CDATA) ;

        if (offset == -1)
            ISOException.throwIt(ISO7816.SW_FILE_INVALID);

        // Clear the card data.
        Util.arrayFillNonAtomic(cardDatabase, offset, SIZE_OF_CARD_DATA_BLOCK, (byte)0) ;
	}
	
	short getCard(byte[] apduBuffer) 
	{

        short p1 = (short) ((short)apduBuffer[ISO7816.OFFSET_P1] & 0xFF) ;

        short cardOffset = findCard(apduBuffer, ISO7816.OFFSET_CDATA) ;
        
        // If the card wasn't found throw an error.
        if (cardOffset < 0)
            ISOException.throwIt(ISO7816.SW_FILE_INVALID);
        
        
        short tlvOffset ;
        short length = 0 ;
        switch(p1) {
	        case 0:
	        	// Stick in the state TLV.
	        	tlvOffset = findTlv(cardOffset, TAG_STATE) ;
	        	if (tlvOffset < 0)
	                ISOException.throwIt(ISO7816.SW_FILE_INVALID);
	        	length = Util.arrayCopyNonAtomic(cardDatabase, tlvOffset, apduBuffer, length, (short)3) ;

	        	// Stick in the UI string TLV.
	        	tlvOffset = findTlv(cardOffset, TAG_UI_STRING) ;
	        	if (tlvOffset < 0)
	                ISOException.throwIt(ISO7816.SW_FILE_INVALID);
	        	
	        	p1 = (short) ((short)cardDatabase[(short)(tlvOffset + 1)] & 0xFF) ;
	        	length = Util.arrayCopyNonAtomic(cardDatabase, tlvOffset, apduBuffer, length, p1) ;
	        	break ;
	        
	        case 1:
	        	// Stick in the AID TLV.
	        	tlvOffset = findTlv(cardOffset, TAG_PAYMENT_AID) ;
	        	if (tlvOffset < 0)
	                ISOException.throwIt(ISO7816.SW_FILE_INVALID);
	        	p1 = (short) ((short)cardDatabase[(short)(tlvOffset + 1)] & 0xFF) ;
	        	length = Util.arrayCopyNonAtomic(cardDatabase, tlvOffset, apduBuffer, length, p1) ;

	        	// Stick in the display name TLV.
	        	tlvOffset = findTlv(cardOffset, TAG_PAYMENT_DISPLAY_NAME) ;
	        	if (tlvOffset > 0)
	        	{
		        	p1 = (short) ((short)cardDatabase[(short)(tlvOffset + 1)] & 0xFF) ;
		        	length = Util.arrayCopyNonAtomic(cardDatabase, tlvOffset, apduBuffer, length, p1) ;
	        	}
	        	break ;
	        
	        case 2:
	        	// Stick in the track 1 TLV.
	        	tlvOffset = findTlv(cardOffset, TAG_TRACK_1_DATA) ;
	        	if (tlvOffset > 0)
	        	{
		        	p1 = (short) ((short)cardDatabase[(short)(tlvOffset + 1)] & 0xFF) ;
		        	length = Util.arrayCopyNonAtomic(cardDatabase, tlvOffset, apduBuffer, length, p1) ;
	        	}
	        	
	        	// Stick in the track 2 TLV.
	        	tlvOffset = findTlv(cardOffset, TAG_TRACK_2_DATA) ;
	        	if (tlvOffset > 0)
	        	{
		        	p1 = (short) ((short)cardDatabase[(short)(tlvOffset + 1)] & 0xFF) ;
		        	length = Util.arrayCopyNonAtomic(cardDatabase, tlvOffset, apduBuffer, length, p1) ;
	        	}
	        	
	        	// Stick in the track 3 TLV.
	        	tlvOffset = findTlv(cardOffset, TAG_TRACK_3_DATA) ;
	        	if (tlvOffset > 0)
	        	{
		        	p1 = (short) ((short)cardDatabase[(short)(tlvOffset + 1)] & 0xFF) ;
		        	length = Util.arrayCopyNonAtomic(cardDatabase, tlvOffset, apduBuffer, length, p1) ;
	        	}
	        	break ;
	        
	        case 3:
	            // Stick in the UI string TLV.
	        	tlvOffset = findTlv(cardOffset, TAG_PAN) ;
	        	if (tlvOffset < 0)
	                ISOException.throwIt(ISO7816.SW_FILE_INVALID);
	        	p1 = (short) ((short)cardDatabase[(short)(tlvOffset + 1)] & 0xFF) ;
	        	length = Util.arrayCopyNonAtomic(cardDatabase, tlvOffset, apduBuffer, (short)0, p1) ;

	        	// Stick in the state TLV.
	        	tlvOffset = findTlv(cardOffset, TAG_CVV) ;
	        	if (tlvOffset > 0)
	        		length = Util.arrayCopyNonAtomic(cardDatabase, tlvOffset, apduBuffer, length, (short)6) ;

	        	// Stick in the state TLV.
	        	tlvOffset = findTlv(cardOffset, TAG_EXPIRY_DATE) ;
	        	if (tlvOffset > 0)
	        		length = Util.arrayCopyNonAtomic(cardDatabase, tlvOffset, apduBuffer, length, (short)7) ;

	        	// Pad the data with 0's
		    	while ((length & 0xF) != 0)
		    		apduBuffer[length++] = 0 ;
		    	
	        	break ;
	        
	        case 4:
	        	// Stick in the state TLV.
	        	tlvOffset = findTlv(cardOffset, TAG_STATE) ;
	        	if (tlvOffset < 0)
	                ISOException.throwIt(ISO7816.SW_FILE_INVALID);
	        	length = Util.arrayCopyNonAtomic(cardDatabase, tlvOffset, apduBuffer, length, (short)3) ;

	        	// Stick in the UI string TLV.
	        	tlvOffset = findTlv(cardOffset, TAG_UI_STRING) ;
	        	if (tlvOffset < 0)
	                ISOException.throwIt(ISO7816.SW_FILE_INVALID);
	        	p1 = (short) ((short)cardDatabase[(short)(tlvOffset + 1)] & 0xFF) ;
	        	length = Util.arrayCopyNonAtomic(cardDatabase, tlvOffset, apduBuffer, length, p1) ;

	        	// Stick in the state TLV.
	        	tlvOffset = findTlv(cardOffset, TAG_CATEGORY) ;
	        	if (tlvOffset > 0)
	        		length = Util.arrayCopyNonAtomic(cardDatabase, tlvOffset, apduBuffer, length, (short)3) ;

	        	// Stick in the state TLV.
	        	tlvOffset = findTlv(cardOffset, TAG_PURPOSE) ;
	        	if (tlvOffset > 0)
	        		length = Util.arrayCopyNonAtomic(cardDatabase, tlvOffset, apduBuffer, length, (short)3) ;

	        	// Stick in the state TLV.
	        	tlvOffset = findTlv(cardOffset, TAG_IMAGE) ;
	        	if (tlvOffset > 0)
	        		length = Util.arrayCopyNonAtomic(cardDatabase, tlvOffset, apduBuffer, length, (short)3) ;
	        	break ;
        }

        return length ;
	}
	
	/**
	 * Finds the card associated with the 3 byte CID passed as an input parameter.
	 * 
	 * @param cid - buffer holding the CID to be located.
	 * @param offset - offset into the buffer pointing to the CID.
	 *
	 * @return the offset into the card table pointing to the specified card or -1
	 *         if not found.
	 */
	private short findCard(byte [] cid, short offset) {
		// Search through the card database to see if the find the specific CID.
		short card = 0 ;
		short cardOffset = 0 ;
		while((card < numberOfCards) && (card < MAX_NUMBER_OF_CARDS)) {
			
			if (Util.arrayCompare(cid, offset, cardDatabase, cardOffset, (short) 3) == 0)
				return cardOffset ;
			
			cardOffset += SIZE_OF_CARD_DATA_BLOCK ;
		}

		// If the card isn't found return a -1.
		return (short) -1;
	}

	/**
	 * Finds a specific TLV in the card information block.
	 * 
	 * @param cardOffset - offset into the card database to the start of the card data.
	 * @param tag - tag to be found.
	 *
	 * @return the offset into the card table pointing to the specified TLV or -1
	 *         if not found.
	 */
	private short findTlv(short cardOffset, byte tag) {
		short length ;
		
		// Move past the CID
		cardOffset += 3 ;

		short cardLength = (short)(cardDatabase[cardOffset++] & 0xFF) ;

		// Look through the card.
		short endStop = (short)(cardOffset + cardLength) ;
		while((cardOffset < endStop)) {
			byte currentTag = cardDatabase[cardOffset] ;
			if (currentTag == tag)
				return cardOffset ;
			
			cardOffset++ ;
	        length = (short) ((short)cardDatabase[cardOffset++] & 0xFF) ;
			cardOffset += length ;
		}

		return (short)-1;
	}

	/**
	 * Appends a TLV to the end of a card.
	 * 
	 * @param cardOffset - offset into the card database to the start of the card data.
	 * @param tlv - TLV to be added.
	 * @param offset - offset to the start of the TLVs to add.
	 * @param tlvLength - length of the TLVs to add.
	 *
	 * @return the offset into the card table pointing to the specified TLV or -1
	 *         if not found.
	 */
	private void appendTlv(short cardOffset, byte [] tlv, short offset, short tlvLength) {
		
		// Move past the CID
		cardOffset += 3 ;
		
		// Get the current card length.
		short cardLength = (short)(cardDatabase[cardOffset++] & 0xFF) ;
		
		// If there is not enough space throw an error.
		if ((short)(cardLength + tlvLength) > MAX_CARD_SIZE)
            ISOException.throwIt(ISO7816.SW_FILE_INVALID);

		// Append the TLV(s) to the end.
		Util.arrayCopyNonAtomic(tlv, offset, cardDatabase, (short)(cardOffset + cardLength + 1), tlvLength);
		
		// Adjust the card length.
		cardLength += tlvLength ;
	}

	/**
	 * Deletes a TLV from the card
	 * 
	 * @param cardStart - offset to the start of the card.
	 * @param tlvOffset - offset to the TLV to be deleted.
	 */
	private void deleteTlv(short cardStart, short tlvOffset) {
		
		// Move past the CID
		cardStart += 3 ;
		
		// Get the current card length.
		short cardLength = (short)(cardDatabase[cardStart] & 0xFF) ;

		// Get the length of the TLV to be deleted - includiing the tag and length.
		short tlvLength = (short)(cardDatabase[(short)(tlvOffset + 1)] & 0xFF) ;
		tlvLength += 2 ;
		
		// Calculate the new card length.
		cardDatabase[cardStart] = (byte)(cardLength - tlvLength) ;
		
		// Move the rest up.
		Util.arrayCopyNonAtomic(cardDatabase, (short)(tlvOffset + tlvLength), cardDatabase, tlvOffset, (short)(cardLength + tlvOffset + tlvLength));
	}

}
