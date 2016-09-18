package com.akm.keystore.generator;


import java.io.FileOutputStream;
import java.net.InetAddress;
import java.security.cert.Certificate;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import sun.security.x509.CertAndKeyGen;
import sun.security.x509.X500Name;
//keytool -genkey -alias alias -keypass mypassword -keystore mykey.keystore -storepass mypassword

public class GenerateKeyStore {

	private static String ALIAS = "MyHttpServer";
	private static String password=getHostName();
	
	public static String getHostName()
	{
		String hostname="127.0.0.1";
		try{
			hostname=InetAddress.getLocalHost().getHostName();
		}catch(Exception e)
		{
			
		}
		return hostname;
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try
		{
		KeyStore keyStore=createUserKeyStore("Ashish");
		FileOutputStream writeStream = new FileOutputStream("mykey.keystore");
		keyStore.store(writeStream, password.toCharArray());
		writeStream.close();
		System.out.println(password);
		}catch(Exception e)
		{
			
		}
	}

	public static KeyStore createUserKeyStore(String storePassword) {
		KeyStore keyStore = null;

		try {
			keyStore = KeyStore.getInstance("JKS");
			// get the alias from the configuration
			String alias = ALIAS;
			// initialize key generator
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
			keyGen.initialize(2048, random);
			// generate a keypair
			KeyPair pair = keyGen.generateKeyPair();
			PrivateKey priv = pair.getPrivate();
			PublicKey pub = pair.getPublic();
			Certificate[] certChain = new Certificate[1];
			// getCertChain(pair, person);
			// generate the user certificate
			X509Certificate cert =  generateCertificate(pair);
			certChain[0]=(Certificate) cert;
			keyStore.load(null,password.toCharArray());
			keyStore.setKeyEntry(alias, priv, password.toCharArray(),certChain); 
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return keyStore;
	}

	private static X509Certificate generateCertificate(KeyPair keyPair) {

		X509Certificate cert = null;
		int validDuration = 365;

		// get user's first and last name
		String firstName = "SelfServer";
		String lastName = "com";

		// backdate the start date by a day
		Calendar start = Calendar.getInstance();
		start.add(Calendar.DATE, -1);
		java.util.Date startDate = start.getTime();
		// what is the end date for this cert's validity?
		Calendar end = Calendar.getInstance();
		end.add(Calendar.DATE, validDuration);
		java.util.Date endDate = end.getTime();

		try {

			CertAndKeyGen keyGen = new CertAndKeyGen("RSA", "SHA256WithRSA",
					null);
			keyGen.generate(2048);
			X500Name subjectName = new X500Name("CN=" + firstName
					+ " " + lastName);
			cert = keyGen.getSelfCertificate(subjectName, endDate.getTime());
			
			
		} catch (Exception ex) {

		}

		return cert;
	}

}
