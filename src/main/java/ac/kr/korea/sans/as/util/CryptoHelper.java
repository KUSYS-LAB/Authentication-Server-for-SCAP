package ac.kr.korea.sans.as.util;

import ac.kr.korea.sans.as.constant.Constants;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;

import javax.annotation.PostConstruct;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

@Component
public class CryptoHelper {
	
	private Logger logger = LoggerFactory.getLogger(CryptoHelper.class); 
	
	private static  CryptoHelper cryptoHelper = new CryptoHelper(); 

	
	public CryptoHelper() {
		
	}

	@PostConstruct
	public void init(){
		Security.addProvider(new BouncyCastleProvider());
	}

	public static CryptoHelper getInstance() {
		return cryptoHelper;
	}

	public X509Certificate getX509Certificate(String path) throws CertificateException, FileNotFoundException {
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		return (X509Certificate) certFactory.generateCertificate(new FileInputStream(new File(path)));
	}

	public X509Certificate convertX509FromBytes(byte[] arr) throws CertificateException {
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(arr));
		return cert;
	}

	public KeyPair generateEcKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());
//    	ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
//		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
		ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
    	SecureRandom random = new SecureRandom();
    	KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
    	keyPairGenerator.initialize(ecSpec, random);
    	KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}
	
	public KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.genKeyPair();
		return keyPair;
	}
	
	public void writeToFile(File output, byte[] toWrite)
			throws IllegalBlockSizeException, BadPaddingException, IOException {
		FileOutputStream fos = new FileOutputStream(output);
		fos.write(toWrite);
		fos.flush();
		fos.close();
	}

	public PublicKey restorePublicKeyFromPem(String pem) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		Reader reader = new StringReader(pem);
		SubjectPublicKeyInfo parser = (SubjectPublicKeyInfo) new PEMParser(reader).readObject();
		return new JcaPEMKeyConverter().getPublicKey(parser);
//		Reader reader = new StringReader(pem);
//		PEMKeyPair parser = (PEMKeyPair) new PEMParser(reader).readObject();
//		return new JcaPEMKeyConverter().getPublicKey(parser.getPublicKeyInfo());
	}

	public PublicKey restorePublicKeyFromPem(FileReader pemReader) throws IOException {
		SubjectPublicKeyInfo parser = (SubjectPublicKeyInfo) new PEMParser(pemReader).readObject();
		return new JcaPEMKeyConverter().getPublicKey(parser);
//		PEMKeyPair parser = (PEMKeyPair) new PEMParser(pemReader).readObject();
//		return new JcaPEMKeyConverter().getPublicKey(parser.getPublicKeyInfo());
	}

	public PrivateKey restorePrivateKeyFromPem(String pem) throws IOException {
		StringReader reader = new StringReader(pem);
		PrivateKeyInfo parser = (PrivateKeyInfo) new PEMParser(reader).readObject();
		return new JcaPEMKeyConverter().getPrivateKey(parser);
	}

	public PrivateKey restorePrivateKeyFromPem(FileReader pemReader) throws IOException {
		PEMKeyPair parser = (PEMKeyPair) new PEMParser(pemReader).readObject();
		return new JcaPEMKeyConverter().getPrivateKey(parser.getPrivateKeyInfo());
	}

	public String convertPublicKeyToPem(PublicKey publicKey) throws IOException {
		StringWriter stringWriter = new StringWriter();
		PemWriter pemWriter = new PemWriter(stringWriter);
		pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
		pemWriter.flush();
		pemWriter.close();
		String pemPublicKey = stringWriter.toString();
		stringWriter.close();

		return pemPublicKey;
	}

	public SecretKey generateAesKey() throws NoSuchAlgorithmException {
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		generator.init(128, random);
		return generator.generateKey();
	}

	public IvParameterSpec generateIv() {
		byte[] iv = new byte[16];
		new SecureRandom().nextBytes(iv);
		return new IvParameterSpec(iv);
	}

	public String encryptWithAes(String data, Key sk, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, sk, iv);

		byte[] dataEnc = cipher.doFinal(data.getBytes());
		return Base64Utils.encodeToString(dataEnc);
	}

	public byte[] decryptWithAes(byte[] data, Key sk, IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, sk, iv);

		return cipher.doFinal(data);
	}

	public String getSignature(byte[] data, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature signature = null;
		if (Constants.TYPE_PKI.toLowerCase().trim().equals("ec")) {
			signature = Signature.getInstance("SHA256withECDSA");
		} else if (Constants.TYPE_PKI.toLowerCase().trim().equals("rsa")) {
			signature = Signature.getInstance("SHA256withRSA");
		}
		signature.initSign(privateKey);
		signature.update(data);
		return Base64Utils.encodeToString(signature.sign());
	}

	public HashMap<String, String> testEcdsa(String msg, String namedCurve, String prv, String kVal, String rVal, String sVal) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException, InvalidKeyException, SignatureException, NoSuchProviderException {
		byte[] input = new BigInteger(msg, 16).toByteArray();
		
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		ECGenParameterSpec kpgparams = new ECGenParameterSpec(namedCurve);
		kpg.initialize(kpgparams);
		java.security.spec.ECParameterSpec params = ((ECPublicKey) kpg.generateKeyPair().getPublic()).getParams();

		//Create the static private key W from the Test Vector
		ECPrivateKeySpec static_privates = new ECPrivateKeySpec(new BigInteger(prv, 16), params);
		KeyFactory kf = KeyFactory.getInstance("EC");
		ECPrivateKey spriv = (ECPrivateKey) kf.generatePrivate(static_privates);
		
		Signature dsa = Signature.getInstance("SHA256withECDSA", "BC");
		FixedSecureRandom k = new FixedSecureRandom(Hex.decode(kVal));
		dsa.initSign(spriv, k);
		dsa.update(input);
		byte[] output = dsa.sign();
		
		ASN1Sequence sequence = ASN1Sequence.getInstance(output);
		ASN1Integer r = (ASN1Integer) sequence.getObjectAt(0);
		ASN1Integer s = (ASN1Integer) sequence.getObjectAt(1);
		logger.info("msg: " + msg);
		logger.info("ncurve: " + namedCurve);
		logger.info("private key: " + prv);
		logger.info("k: " + kVal);
		logger.info("r(prd): " + r.getValue().toString(16));
		logger.info("s(prd): " + s.getValue().toString(16));
		logger.info("r(cor): " + rVal);
		logger.info("s(cor): " + sVal);
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("msg", msg);
		map.put("ncurve", namedCurve);
		map.put("private-key", prv);
		map.put("k", kVal);
		map.put("r-get", r.getValue().toString(16));
		map.put("s-get", s.getValue().toString(16));
		map.put("r-cor", rVal);
		map.put("s-cor", sVal);
		map.put("signature", Hex.toHexString(output));
		return map;
	}
	
	public HashMap<String, String> testRsaPss(String msg, String nVal, String dVal, String sig) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {
		byte[] input = new BigInteger(msg, 16).toByteArray();
		KeyFactory kf = KeyFactory.getInstance("RSA");
		RSAPrivateKeySpec static_privates = new RSAPrivateKeySpec(
				new BigInteger(nVal, 16), 
				new BigInteger(dVal, 16));
		
		PrivateKey spriv = kf.generatePrivate(static_privates);
		Signature dsa = Signature.getInstance("SHA256withRSA");
		dsa.initSign(spriv);
		dsa.update(input);
		byte[] output = dsa.sign();
		logger.info("msg: " + Hex.toHexString(output));
		logger.info("n: " + nVal);
		logger.info("d: " + dVal);
		logger.info("sig-cor: " + sig);
		logger.info("sig-get: " + Hex.toHexString(output));
		
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("msg", msg);
		map.put("n", nVal);
		map.put("d", dVal);
		map.put("sig-cor", sig);
		map.put("sig-get", Hex.toHexString(output));
		
		return map;
	}
}
