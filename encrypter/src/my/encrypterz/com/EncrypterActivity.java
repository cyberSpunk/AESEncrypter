package my.encrypterz.com;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.telephony.SmsManager;
import android.util.Base64;
import android.view.View;
import android.widget.EditText;
import android.widget.RadioButton;
import android.widget.Toast;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
//import org.bouncycastle.asn1.x509.Certificate;
//import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
//import org.bouncycastle.asn1.x509.X509Name;
//import org.bouncycastle.jce.X509Principal;
//import org.bouncycastle.x509.X509V1CertificateGenerator;
//import org.bouncycastle.x509.X509V3CertificateGenerator;



@SuppressWarnings("deprecation")
public class EncrypterActivity extends Activity {
    /** Called when the activity is first created. */
	private static KeyStore ks;
	private static java.io.FileInputStream fis = null;
	private Context cxt;
	private static String salt = "mysalt";
	private static int pswdIterations = 16;
	private static int keySize = 256;
	private static final String password = "integrals00";
	private static String result="";
	@Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
    }
    
    public void DataSec(Context cxt){
    	this.cxt=cxt;
    }
    
    public void encrypts(View view) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableEntryException, NoSuchProviderException, CertificateException, IOException {
    	EditText text = (EditText)findViewById(R.id.gettext);
    	String value = text.getText().toString();
    	String stringToConvert = value; byte[] 
    	theByteArray = stringToConvert.getBytes();
    	int flags = 0;
		String s = Base64.encodeToString(theByteArray, flags);
    	EditText editText = (EditText)findViewById(R.id.gettext);
    	editText.setText(s,EditText.BufferType.EDITABLE);

    }
    

    
    
  //# this function encrypts the text with 128 bit encryption	
  	public void encrypt(View view) throws
      NoSuchAlgorithmException,
      InvalidKeySpecException,
      NoSuchPaddingException,
      InvalidParameterSpecException,
      IllegalBlockSizeException,
      BadPaddingException,
      InvalidKeyException,
      InvalidAlgorithmParameterException, IOException, UnrecoverableKeyException, KeyStoreException, CertificateException, NoSuchProviderException, IllegalStateException, SignatureException
  {  
  	  byte[] saltBytes = salt.getBytes("UTF-8");
      byte[] ivBytes = new byte[16];
      EditText text = (EditText)findViewById(R.id.gettext);
  	  String value = text.getText().toString();
  	  String stringToConvert = value; byte[] 
  	  theByteArray = stringToConvert.getBytes();
  	  int flags = 0;
	  //String s = Base64.encodeToString(theByteArray, flags);
  	  
      // Derive the key, given password and salt.
      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
      PBEKeySpec spec = new PBEKeySpec(
              password.toCharArray(),
              saltBytes,
              pswdIterations,
              keySize
      );
      
      
      
      
      
      
      
      
      // GENERATE THE PUBLIC/PRIVATE RSA KEY PAIR
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
      keyPairGenerator.initialize(1024, new SecureRandom());

    //  KeyPair keyPair = keyPairGenerator.generateKeyPair();

      // GENERATE THE X509 CERTIFICATE
      //ASN1CertificateGenerator certGen = new ASN1V1CertificateGenerator();
//      X509Name dnName = new X509Name("CN=John Doe");
//
//      certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
//      certGen.setSubjectDN(dnName);
//      certGen.setIssuerDN(dnName); // use the same
//      certGen.setNotBefore(validityBeginDate);
//      certGen.setNotAfter(validityEndDate);
//      certGen.setPublicKey(keyPair.getPublic());
//      certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
//
//      X509Certificate cert = certGen.generate(keyPair.getPrivate(), "BC");
      

//  
//    	   X509V3CertificateGenerator cert = new X509V3CertificateGenerator();   
//    	   cert.setSerialNumber(BigInteger.valueOf(1));   //or generate a random number  
//    	   cert.setSubjectDN(new X509Principal("CN=localhost"));  //see examples to add O,OU etc  
//    	   cert.setIssuerDN(new X509Principal("CN=localhost")); //same since it is self-signed  
//    	   cert.setPublicKey(keyPair.getPublic());  
//    	   cert.setNotBefore(validityBeginDate);  
//    	   cert.setNotAfter(validityEndDate);  
//    	   cert.setSignatureAlgorithm("SHA1WithRSAEncryption");   
//    	    PrivateKey signingKey = keyPair.getPrivate();    
//    	   Certificate newcert = cert.generate(signingKey, "BC");  
      Certificate j = null;
      
      byte[] newbyte={'A','n','%','/','6','I','@','M'};
      java.security.cert.Certificate[] chain = new java.security.cert.Certificate[1];
      chain[0]=j;
      SecretKey secretKey = factory.generateSecret(spec);
      SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
       
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(ivBytes));
   
      byte[] encryptedTextBytes = cipher.doFinal(stringToConvert.getBytes("UTF-8"));
      String result = Base64.encodeToString(encryptedTextBytes, Base64.DEFAULT);
      //String e= new sun.misc.Base64().encode(encryptedTextBytes);
      EditText editText = (EditText)findViewById(R.id.gettext);
  	  editText.setText(result,EditText.BufferType.EDITABLE);
  	  
  	Context ctx = getBaseContext();
  	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		keyGen.initialize(1024, random);
		KeyPair pair = keyGen.generateKeyPair();
		PrivateKey priv = pair.getPrivate();
		PublicKey pub = pair.getPublic();
		
  	
  	char[] password = {'i','n','t','e','g','r','a'};
  	//File file=File(pathname);
  	//KeyStore.Builder o = newInstance("BKS", provider, , new KeyStore.PasswordProtection(password));
  	ks=KeyStore.getInstance(KeyStore.getDefaultType());
  	try {
  	    //fis = new java.io.FileInputStream("bs.keystore");
  	    ks.load(fis,password);
  	} catch (FileNotFoundException e) {
  		ks.load(null);
			e.printStackTrace();
  	}
  		//Context context = null;
			//KeyStore.PrivateKeyEntry pkentry = new KeyStore.PrivateKeyEntry(priv, chain);
			SecretKey key;
			key = KeyGenerator.getInstance("AES").generateKey();
			//KeyStore.PrivateKeyEntry privkeyentry = new KeyStore.PrivateKeyEntry(key, chain);
			String stringKey = Base64.encodeToString(priv.getEncoded(), Base64.DEFAULT);
			Toast.makeText(EncrypterActivity.this,  stringKey, Toast.LENGTH_LONG).show();
  		KeyStore.SecretKeyEntry skEntry =
  	    new KeyStore.SecretKeyEntry(key);
  	try {
  		//ks.setKeyEntry("secretKeyAlias", newbyte, chain);
			//ks.setEntry("ParsedCloud Storage private key", skEntry, 
			 //   new KeyStore.PasswordProtection(password));
			ks.setEntry("ParsedCloud Storage public key", skEntry, 
				    new KeyStore.PasswordProtection(password));
			//ks.setKeyEntry("ParsedCloud Storage public key", newbyte, chain);
			//ks.setKeyEntry("secretKeyAlias", priv, password, chain);
			//ks.setKeyEntry("secretKeyAlias", pub, password, chain);
			//ks.setKeyEntry("ParsedCloud Storage the key", (Key)pair.getPrivate(), password, chain);  
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
  	//char[] a=pass.toCharArray();
  	Key k = ks.getKey("ParsedCloud Storage public key", password);
  	//ks.getEntry("secretKeyAlias", protperam);
  	String stringer = Base64.encodeToString(k.getEncoded(), Base64.DEFAULT);
  	Toast.makeText(EncrypterActivity.this,  ks.getProvider().toString(), Toast.LENGTH_LONG).show();
  	Toast.makeText(EncrypterActivity.this,  stringer, Toast.LENGTH_LONG).show();
  	// store away the keystore
  	FileOutputStream fos;
  	ks.setEntry("secretKeyAlias", skEntry, 
   	new KeyStore.PasswordProtection(password));
  	//fos=null;
  	try{
  		
  	   fos = openFileOutput("my-release-keystore", Context.MODE_PRIVATE);
  	   ks.store(fos, password);
  	   fos.close();
  	}catch (Exception e){
  	//Entry r = ks.getEntry("secretKeyAlias", new KeyStore.PasswordProtection(password));
		e.printStackTrace();
  	}
  	Key i = ks.getKey("ParsedCloud Storage public key", password);
  	stringer = Base64.encodeToString(i.getEncoded(), Base64.DEFAULT);
  	Toast.makeText(EncrypterActivity.this,  stringer, Toast.LENGTH_LONG).show();
  	  
  	  
  	  
  }
    
    
    
    
    public void decrypts(View view) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, IOException { 	
    	int flags =0; String context="message sent";
    	EditText text = (EditText)findViewById(R.id.gettext);
    	String back = text.getText().toString();
    	byte[] strs = Base64.decode(back, flags);
    	String edecrypt = new String (strs).toString();
    	EditText editText = (EditText)findViewById(R.id.gettext);
    	
    	
    }
    

	public void decrypt(View view) throws
    NoSuchAlgorithmException,
    InvalidKeySpecException,
    NoSuchPaddingException,
    InvalidKeyException,
    InvalidAlgorithmParameterException,
    IOException, IllegalBlockSizeException, BadPaddingException, KeyStoreException, CertificateException, UnrecoverableKeyException
{
		EditText text = (EditText)findViewById(R.id.gettext);
    	String back = text.getText().toString();
		byte[] saltBytes = salt.getBytes("UTF-8");
	    byte[] ivBytes = new byte[16];
	    int flag =0;
	    byte[] encryptedTextBytes = Base64.decode(back,flag);
	     
	    // Derive the key, given password and salt.
	    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
	    PBEKeySpec spec = new PBEKeySpec(
	            password.toCharArray(),
	            saltBytes,
	            pswdIterations,
	            keySize
	    );
	 
	    SecretKey secretKey = factory.generateSecret(spec);
	    SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
	 
	    // Decrypt the message, given derived key and initialization vector.
	    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	    cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivBytes));
	 
	    byte[] decryptedTextBytes = null;
	    try {
	        decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
	    } catch (IllegalBlockSizeException e) {
	        e.printStackTrace();
	    } catch (BadPaddingException e) {
	        e.printStackTrace();
	    }
	    
	    
	    String edecrypt = new String (decryptedTextBytes).toString();
	      EditText editText = (EditText)findViewById(R.id.gettext);
	  	  editText.setText(edecrypt,EditText.BufferType.EDITABLE);
	  	  
	  	  
	  	char[] password = {'i','n','t','e','g','r','a'};
    	ks=KeyStore.getInstance(KeyStore.getDefaultType());
    	try{
    	fis= openFileInput("my-release-keystore");
    	ks.load(fis,password);
    	}catch (Exception e){
    		ks.load(null);
    		e.printStackTrace();
        	}
    	Key i = ks.getKey("ParsedCloud Storage public key", password);
    	//ks.get
    	String stringer = Base64.encodeToString(i.getEncoded(), Base64.DEFAULT);
   	    stringer = Base64.encodeToString(i.getEncoded(), Base64.DEFAULT);
   	    Toast.makeText(EncrypterActivity.this,  stringer, Toast.LENGTH_LONG).show();
}
    
    
    public void email(String phnum,String msg){
    	Intent email = new Intent(Intent.ACTION_SEND);
    	email.putExtra(Intent.EXTRA_EMAIL, phnum);		
    	email.putExtra(Intent.EXTRA_SUBJECT, "subject");
    	email.putExtra(Intent.EXTRA_TEXT, msg);
    	email.setType("message/rfc822");
    	startActivity(Intent.createChooser(email, "Choose an Email client :"));
    	
    }
    
    public void text(View view) {
    	EditText text = (EditText)findViewById(R.id.editText1);
    	String phnum = text.getText().toString();
    	String messagesent="message Sent";
    	String emailmessagesent="Email Message Sent";
    	String emailmessagenotsent="Please enter a recipient";
    	String messagenotsent="please enter a phone number";
    	EditText txt = (EditText)findViewById(R.id.gettext);
    	String msg = txt.getText().toString();
    	// here is where the destination of the text should go
    	RadioButton textrb;
    	RadioButton emailrb;
    	boolean checked=true;
    	boolean unchecked=false;
    	textrb=(RadioButton)findViewById(R.id.textradiobutton);
    	emailrb=(RadioButton)findViewById(R.id.emailradiobutton);
    	if(textrb.isChecked()){
    	  if (text.getText().toString().equals(""))
    	    {
    		Toast.makeText(this, messagenotsent, Toast.LENGTH_SHORT).show();
    	    }
    	  else{
    		   sendmessage(phnum,msg);
    		   Toast.makeText(this, messagesent, Toast.LENGTH_SHORT).show();    		
    	      }
    	}
    	else if(emailrb.isChecked()){
        	if (text.getText().toString().equals(""))
        	{
        		Toast.makeText(this, emailmessagenotsent, Toast.LENGTH_SHORT).show();
        	}
        	else{
        		email(phnum,msg);    		
        	}
        	}
    }
    public void sendmessage(String phnum,String msg){
    	SmsManager sm = SmsManager.getDefault();
    	sm.sendTextMessage(phnum, null, msg, null, null);
    }
    public void textradiobuttoncheck(View view){
    	RadioButton textrb;
    	RadioButton emailrb;
    	boolean checked=true;
    	boolean unchecked=false;
    	textrb=(RadioButton)findViewById(R.id.textradiobutton);
    	emailrb=(RadioButton)findViewById(R.id.emailradiobutton);
    	emailrb.setChecked(unchecked);    	
    	//textrb.setChecked(checked);    	
    }
    
    public void emailradiobuttoncheck(View view){
    	RadioButton textrb;
    	RadioButton emailrb;
    	boolean checked=true;
    	boolean unchecked=false;
    	textrb=(RadioButton)findViewById(R.id.textradiobutton);
    	emailrb=(RadioButton)findViewById(R.id.emailradiobutton);
    	textrb.setChecked(unchecked);
    	//emailrb.setChecked(checked);
    	
    }
    
            
    public void clear(View view) {
    	EditText editText = (EditText)findViewById(R.id.gettext);
    	editText.setText("",EditText.BufferType.EDITABLE);
    	
		EditText ditText = (EditText)findViewById(R.id.gettext);
    	ditText.setText("",EditText.BufferType.EDITABLE);
    }
}
