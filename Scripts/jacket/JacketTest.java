package com.radiius.jacket.scripts;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.helixion.globalplatform.GPConstants;
import com.helixion.globalplatform.GPLoader;
import com.helixion.globalplatform.GP_SCP;
import com.helixion.lok.logger.LogLineType;
import com.helixion.lok.scriptmanager.ScriptManager;
import com.helixion.lok.scripts.JavaScript;
import com.helixion.lok.scripts.ScriptResults;
import com.helixion.lok.scripts.ScriptRunStates;
import com.helixion.lok.scripts.ScriptTypes;
import com.helixion.lok.testcomponent.carddetails.CardDetails;
import com.helixion.lok.testcomponent.carddetails.CardDetailsTestComponent;
import com.helixion.lok.utils.ByteArray;
import com.helixion.smartcardio.cardreader.CardInterface;
import com.helixion.smartcardio.cardreader.CardReaderTestComponent;

/**
 * This test has to trigger an CDI check in the PM.
 *
 * As it's the first one after personalisation and the IURO has been set to
 * trigger a interval based Issuer Update this should fire off an Issuer Update.
 *
 * @author Steve Harkins
 */
public abstract class JacketTest extends JavaScript  {

	protected static int    STATE          = 1 ;
	protected static int    UI_STRING      = 2 ;
	protected static int    TRACK_1        = 3 ;
	protected static int    TRACK_2        = 4 ;
	protected static int    TRACK_3        = 5 ;
	protected static int    CARD_AID       = 6 ;
	protected static int    LABEL          = 7 ;
	protected static int    PAN            = 8 ;
	protected static int    CVV            = 9 ;
	protected static int    EXP_DATE       = 10 ;
	protected static int    CATEGORY       = 11 ;
	protected static int    PURPOSE        = 12 ;
	protected static int    IMAGE          = 13 ;

	protected static int    AES_KEY_LENGTH = 32 ;

	private   static String PACKAGE_AID  = "524144000000" ;
	protected static String APPLET_AID   = "5241440000000010" ;
	protected static String INSTANCE_AID = "524144000000001001" ;

	// Fields that will be personalised.
	protected static final byte [] deviceFp   = {1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0} ;
	protected static final byte [] cardHash   = {1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1, 2} ;
	protected static final byte [] jacketHash = {1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 3, 4} ;
	protected static final byte [] aesMKey    = {1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 5, 6} ;
	protected static final byte [] jacketPin  = {0x31, 0x32, 0x33, 0x34} ;

	protected byte [] apduBuffer = new byte[261] ;
	protected byte [] cid        = {1,2,3} ;
	protected byte [] uiString   = new byte [13] ;
	protected byte [] track1     = new byte[79] ;
	protected byte [] track2     = new byte[40];
	protected byte [] track3     = new byte[107];
	protected byte [] aid        = new byte[16];
	protected byte [] label      = new byte[32] ;
	protected byte [] pan        = ByteArray.hexStrToBytes("31323334343332313132333434333231") ;
	protected byte [] cvv        = {'1', '2', '3', '4' } ;
	protected byte [] expDate    = {'1', '2', '=', '3', '4' } ;

	/*
	 * I've generated a test RSA key pair of the required length - need both to do the testing.
	 */
	protected static int        RSA_KEY_SIZE = 248 ;

	private   static BigInteger pubExp   = new BigInteger("65537") ;
	private   static BigInteger pubMod   = new BigInteger("1449460418965878115380401122390848591722180502024356142676271965109677617389695709457960435269366802957184133432029595986413659252457726593947228386213769298059458570287341154034933242104045556971577104445709491151654986628783710122578708065164521169653080107599686538447801559798516797676173632427852747992043686850812888346808332507528302337872171116261090379303129404394198556099829622458034123975281681287321852734400304706530683641545651166157492339400937412063061916148630709796782430807521522622141006184233735404188971304820907128667141676361046105807157957610204595209804787605699095979057") ;


	private   static BigInteger primeP     = new BigInteger("40454532661014923488610052872840468427746592222565324266236776120696585029816154501889416561265943167345063900020544402210973239238494554550936102232066563020406458211787937454064703799290345166016036567535629276480823839353433979059958211977819932462784958588748933682882282422312715499789300428957") ;
	private   static BigInteger primeQ     = new BigInteger("35829370001910536127878277269369961724135558418716689110251709221693126513615877549581767711824306454463684861958890709304675630142175056368642939171093971179367989859900199036986166204543426298183069485496111171498763242027885097551943743354564855526220240389567087759944755389935742477913731259301") ;
	private   static BigInteger primExpP   = new BigInteger("3445644465169069425109805379193363973994559985753996064118493130685388980826613583617601099302477909579629013990794190352650451217316578474805458331315067134289162606439114803371975778684387547747097305643894023548773344389747294980128579874882751163575776108799556705644886102222402275353218410889") ;
	private   static BigInteger primExpQ   = new BigInteger("28138878404539959023176143721172344323683677797447975777113012094550333729890126454933451090644934208328819748310482701495516344712418178300716420939869183767979468667913747111306254093837834377031029592726014953339965882893254893739392167332338268671659608661534980347046043607732924383756042356473") ;
	private   static BigInteger coeff      = new BigInteger("5027107793557016044559376329735173094288781486878418293012333273224913456187022432795274180107466710659184265387508760000972284683372954386327014221366335463357105164925799417397740222235853960927661769289530543471247281172948542672637247117001088772534493162166895125770641737231835067076187051799") ;
	private   static BigInteger expBytes   = new BigInteger("65537") ;
	private   static BigInteger modBytes   = new BigInteger("1449460418965878115380401122390848591722180502024356142676271965109677617389695709457960435269366802957184133432029595986413659252457726593947228386213769298059458570287341154034933242104045556971577104445709491151654986628783710122578708065164521169653080107599686538447801559798516797676173632427852747992043686850812888346808332507528302337872171116261090379303129404394198556099829622458034123975281681287321852734400304706530683641545651166157492339400937412063061916148630709796782430807521522622141006184233735404188971304820907128667141676361046105807157957610204595209804787605699095979057") ;

	private   RSAPublicKey            jacketPubKey = null ;

	/**
     * These attributes are set by the test case that implements this abstract
     * class.
     */
    protected String                  scriptName              = "No Name";
    protected String                  scriptDescription       = "No Description";

    protected CardInterface           isoReader = null;

    private   GP_SCP                  sChannel = null;

    protected boolean                 stoppedTest             = false;

    public JacketTest(ScriptManager scriptmanager) {
        super(scriptmanager);
        Arrays.fill(uiString, (byte)0) ;
        Arrays.fill(track1,   (byte)track1.length) ;
        Arrays.fill(track2,   (byte)track2.length) ;
        Arrays.fill(track3,   (byte)track3.length) ;
        Arrays.fill(label,    (byte)label.length) ;
        Arrays.fill(aid,      (byte)aid.length) ;
    }

    /* (non-Javadoc)
     * @see com.helixion.lok.scripts.Script#getPackage()
     */
    public String[] getPackageTree() {
        return new String[] {"Radiius", "Jacket"} ;
    }

    /* (non-Javadoc)
     * @see com.helixion.lok.scripts.Script#getName()
     */
    public String getName() {
        return scriptName ;
    }

    /* (non-Javadoc)
     * @see com.helixion.lok.scripts.Script#getDescription()
     */
    public String getDescription() {
        return scriptDescription ;
    }

    /* (non-Javadoc)
     * @see com.helixion.lok.scripts.Script#getScriptType()
     */
    public ScriptTypes getScriptType() {
        return ScriptTypes.PROTECTED;
    }

    /**
     * This is the method that implements the test.
     * <p>
     * It is invoked from the <code>run()</code> method and must throw an
     * exception if it detects a failure when running the script.
     *
     * @throws Exception
     *             if an error is detected when running the script.
     */
    public abstract void runTest() throws Exception;

    /* (non-Javadoc)
     * @see com.helixion.lok.scripts.JavaScript#run()
     */
    public void run()
    {
        boolean isSuccess = true;
        stoppedTest = false;
        setRunState(ScriptRunStates.PRECONDITIONS);

        try
        {
            setRunState(ScriptRunStates.TESTSCRIPTS);

        	// Delete the card and re-perso.
            initialise();

            // Run the test script - it will throw an exception if an error is detected.
            this.runTest();
        }
        catch (Exception e)
        {
            isSuccess = false;

            log(LogLineType.TRACE, "Error: " + e.getMessage());
        }
        finally
        {
            setRunState(ScriptRunStates.POSTCONDITIONS);

            setRunState(ScriptRunStates.RESULT);

            // Post the test result - unless the test was cancelled half way
            // through.
            if (stoppedTest)
            {
                log(LogLineType.RESULT, ScriptResults.TERMINATED.toString());
            }
            else
            {
                log(LogLineType.RESULT,
                    isSuccess ? ScriptResults.PASS.toString()
                             : ScriptResults.FAILED.toString());
            }

            finalise();
        }
    }

    private void initialise() throws Exception {

        try
        {
//        	KeyPair kp = generateKeyPair("RSA", 1984) ;
//
//    		System.out.println(kp.getPublic());
//    		System.out.println(kp.getPrivate());

        	// Build the default RSA public key that matches the jacket.
        	jacketPubKey = buildRsaKey(pubMod, pubExp) ;

//    		System.out.println(jacketPubKey.toString());

            // Get the card reader type and establish connection to the ISO and SWP interfaces.
            CardReaderTestComponent cardType = (CardReaderTestComponent)getInstanceOfTestComponent("cardreader") ;
            if (null == cardType)
                throw new Exception("Script error: no card reader selected.") ;

            isoReader = cardType.getCardInterface("iso") ;
            if (null == isoReader)
                throw new Exception("Script error: no card detected.") ;

            // Get a reference to the SIM card.
            CardDetailsTestComponent cardComponent  = (CardDetailsTestComponent)getInstanceOfTestComponent("carddetails.loksim");
            CardDetails cardDetails = cardComponent.getCardDetails() ;

            // Create a new instance of the GP_SCP using the card details to extract the relevant information.
            sChannel = new GP_SCP(cardDetails) ;

            // Open a channel to the card manager.
            sChannel.open(isoReader,
                          cardDetails.getSID(),
                          cardDetails.getDefaultKvn(),
                          0,
                          GPConstants.SCP_ANY,
                          cardDetails.getSecurityLevel());

            // Create an instance of the GP loader.
            GPLoader gpLoader = new GPLoader(sChannel, false ) ;

            try {
                gpLoader.deleteAID(INSTANCE_AID, true);
            } catch (Exception e) {
                gpLoader.deleteAID(INSTANCE_AID, true);
            }

            try {
                gpLoader.deleteAID(APPLET_AID, true);
            } catch (Exception e) {
                gpLoader.deleteAID(APPLET_AID, true);
            }

            // Install a new instance.
            gpLoader.installApplet(PACKAGE_AID, APPLET_AID, INSTANCE_AID, 0, null, null) ;

            sChannel.close()  ;

            // Open a secure channel to the VMPA instance.
            sChannel.open(isoReader, INSTANCE_AID, cardDetails.getDefaultKvn(), 0, GPConstants.SCP_ANY, GPConstants.APDU_MAC);

            // Issue the put data commands to the applet.
            sChannel.sendApdu(0x80, 0xDA, 0x00, 0x01, jacketHash, 0) ;
            sChannel.sendApdu(0x80, 0xDA, 0x00, 0x02, cardHash, 0) ;
            sChannel.sendApdu(0x80, 0xDA, 0x00, 0x04, aesMKey, 0) ;
            sChannel.sendApdu(0x80, 0xDA, 0x00, 0x08, jacketPin, 0) ;

            stripSign(0x00, 0x10, coeff) ;
            stripSign(0x00, 0x20, primExpQ) ;
            stripSign(0x00, 0x40, primExpP) ;
            stripSign(0x00, 0x80, primeQ) ;
            stripSign(0x81, 0x00, primeP) ;

//            isoReader.sendApdu(0x80, 0xDA, 0x02, 0x00, expBytes.toByteArray(), 0) ;
//            isoReader.sendApdu(0x80, 0xDA, 0x84, 0x00, modBytes.toByteArray(), 0) ;

        }
        finally
        {
            // Close the secure channel.
            if (null != sChannel)
                sChannel.close();
            sChannel = null ;  ;

        }
    }

    private void stripSign(int tag1, int tag2, BigInteger value) throws Exception {
        byte [] bytes = new byte [0x7C] ;
        byte [] signBytes = value.toByteArray() ;

        if (signBytes.length == 0x7D)
        {
        	System.arraycopy(signBytes, 1, bytes, 0, 0x7C) ;
            sChannel.sendApdu(0x80, 0xDA, tag1, tag2, bytes, 0) ;
        }
        else
            sChannel.sendApdu(0x80, 0xDA, tag1, tag2, signBytes, 0) ;
    }

    public void finalise()
    {
        // Close the secure channel.
        if (null != sChannel)
            sChannel.close();

        if (null != isoReader) {
            try {
                isoReader.reset() ;
            } catch (Exception e) {
            }

            // Release the card.
            try {
                isoReader.close() ;
            } catch (Exception e) {
            }
        }
        isoReader = null ;
    }

    protected byte[] encrypt(int random, byte[] plainText) throws Exception
	{
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		SecretKeySpec keySpec = setSessionKey(random) ;
		byte[] iv = new byte[16];
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
		return cipher.doFinal(plainText);
	}

	protected byte[] decrypt(int random, byte[] cipherText) throws Exception
	{
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		SecretKeySpec keySpec = setSessionKey(random) ;
		byte[] iv = new byte[16];
		cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
		return cipher.doFinal(cipherText) ;
	}

	protected byte[] decrypt(byte[] cipherText) throws Exception
	{
		byte [] keyBuffer = new byte [32] ;
		Arrays.fill(keyBuffer, (byte)0x11) ;
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		SecretKeySpec keySpec = new SecretKeySpec(keyBuffer, "AES");
		byte[] iv = new byte[16];
		cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
		return cipher.doFinal(cipherText) ;
	}

	private SecretKeySpec setSessionKey(int random) throws Exception {

		byte [] tmpBuffer = new byte[AES_KEY_LENGTH];

		// Initialise the key derivation data to all 0.
		Arrays.fill(tmpBuffer, (byte)0) ;

		// Write the RND at the start of the buffer.
		ByteArray.putShortBE( random, tmpBuffer, 0) ;
		ByteArray.putShortBE((~random & 0xFFFF), tmpBuffer, AES_KEY_LENGTH >> 1) ;

		// Encrypt using the master key.
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		SecretKeySpec keySpec = new SecretKeySpec(aesMKey, "AES");
		byte[] iv = new byte[16];
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));

		// Encrypt using the master key.
		tmpBuffer = cipher.doFinal(tmpBuffer) ;

		return new SecretKeySpec(tmpBuffer, "AES");
	}

	protected RSAPublicKey buildRsaKey(BigInteger modulus, BigInteger exponent) throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, pubExp);
		return (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);
	}

    protected byte[] rsaEncrypt(byte [] payload) throws Exception
	{
		Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, jacketPubKey);
		return cipher.doFinal(payload);
	}

    private static KeyPair generateKeyPair(String algorithm, int keysize)
   	       throws NoSuchAlgorithmException {

   	   KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
   	   keyGen.initialize(keysize);

      	return keyGen.genKeyPair();
   	}



}
