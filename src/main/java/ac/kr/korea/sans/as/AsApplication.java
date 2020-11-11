package ac.kr.korea.sans.as;

import ac.kr.korea.sans.as.constant.Constants;
import ac.kr.korea.sans.as.util.CryptoHelper;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.HttpClientBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.util.Base64Utils;

import javax.annotation.PostConstruct;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.*;
import java.net.URISyntaxException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;

@SpringBootApplication
public class AsApplication {
	@Value("${publickey.type}")
	private String publicKeyType;

	@Value("${ca.domain}")
	private String caDomain;

	private static final Logger logger = LoggerFactory.getLogger(AsApplication.class);

	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		SpringApplication.run(AsApplication.class, args);
	}

	@PostConstruct
	public void init() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, IOException, URISyntaxException, CertificateException, NoSuchProviderException {
		TimeZone.setDefault(TimeZone.getTimeZone("Asia/Seoul"));
		Constants.GLOBAL_SECRETKEY_MAP = new HashMap<>();

		if (!new File("AS-KeyPair").exists()) {
			logger.info("create a key pair");
			new File("AS-KeyPair").mkdir();
			CryptoHelper cryptoHelper = CryptoHelper.getInstance();

			if (publicKeyType.equals("ec") || publicKeyType.equals("rsa")) {
				KeyPair keyPair = null;
				if (publicKeyType.toLowerCase().trim().equals("ec")) keyPair = cryptoHelper.generateEcKeyPair();
				else if (publicKeyType.toLowerCase().trim().equals("rsa")) keyPair = cryptoHelper.generateRsaKeyPair();

				JcaPEMWriter pubPemWriter = new JcaPEMWriter(new FileWriter("AS-KeyPair/AS-PublicKey.pem"));
				pubPemWriter.writeObject(keyPair.getPublic());
				pubPemWriter.close();

				JcaPEMWriter prvPemWriter = new JcaPEMWriter(new FileWriter("AS-KeyPair/AS-PrivateKey.pem"));
				prvPemWriter.writeObject(keyPair.getPrivate());
				prvPemWriter.close();

				BufferedReader pubPemReader = new BufferedReader(new FileReader("AS-KeyPair/AS-PublicKey.pem"));
				String publicKeyPem = "";
				String tmp = null;
				while ((tmp = pubPemReader.readLine()) != null) {
					publicKeyPem += (tmp + "\n");
				}
				publicKeyPem = publicKeyPem.substring(0, publicKeyPem.lastIndexOf('\n'));
				pubPemReader.close();

				Map<String, String> json = new HashMap<String, String>();
				json.put(Constants.AS_WEB_PUB, publicKeyPem);
				json.put(Constants.AS_WEB_FIRST_NAME, "authentication server");
				json.put(Constants.AS_WEB_LAST_NAME, "korea university");
				json.put(Constants.AS_WEB_COUNTRY_CODE, "KOR");
				ObjectMapper mapper = new ObjectMapper();

				HttpClient httpClient = HttpClientBuilder.create().build();
				logger.info(caDomain + Constants.URL_GET_CERT);
				HttpPost post = new HttpPost(caDomain + Constants.URL_GET_CERT);
				post.addHeader("content-type", "application/json");
				post.setEntity(new StringEntity(mapper.writeValueAsString(json)));
				ResponseHandler<String> responseHandler = new BasicResponseHandler();
				String response = httpClient.execute(post, responseHandler);

				Map<String, String> respJson = mapper.readValue(response, Map.class);

				X509Certificate cert = cryptoHelper.convertX509FromBytes(Base64Utils.decodeFromString(respJson.get("data")));
				cryptoHelper.writeToFile(new File("AS-KeyPair/AS-Cert.der"), cert.getEncoded());

			} else logger.info("incorrect the public key type(er or rsa)");
		}
	}

}
