package ac.kr.korea.sans.as.service;

import ac.kr.korea.sans.as.constant.Constants;
import ac.kr.korea.sans.as.dao.MemberMapper;
import ac.kr.korea.sans.as.dto.MemberDto;
import ac.kr.korea.sans.as.dto.SecretDto;
import ac.kr.korea.sans.as.restresponse.AsAppResponse;
import ac.kr.korea.sans.as.util.CryptoHelper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.Base64Utils;
//import sun.java2d.pipe.SpanShapeRenderer;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

@Service
public class AuthenticationService {
    @Autowired private MemberMapper memberMapper;
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);
    private MemberDto authTarget;

    public boolean verifySignature(Map<String, Object> body, String signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, InvalidKeySpecException {
        ObjectMapper mapper = new ObjectMapper();
        CryptoHelper cryptoHelper = CryptoHelper.getInstance();
//        logger.info((String) body.get(Constants.AS_WEB_CPK));
        PublicKey publicKey = cryptoHelper.restorePublicKeyFromPem((String) body.get(Constants.AS_WEB_CPK));

        String bodyStr = mapper.writeValueAsString(body);
        byte[] sigBytes = Base64.decode(signature);
        byte[] data = bodyStr.getBytes();

        Signature sig1 = Signature.getInstance("SHA256withRSA");
        sig1.initVerify(publicKey);
        sig1.update(data);
        return sig1.verify(sigBytes);
    }

    public boolean verifyTicket(String ticket, String cname, SecretDto secretDto) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {
        CryptoHelper cryptoHelper = CryptoHelper.getInstance();
        Map<String, Object> ticketMap = this.convertJsonToMap(new String(cryptoHelper.decryptWithAes(Base64Utils.decodeFromString(ticket), secretDto.getSk(), secretDto.getIv())));

        return ticketMap.get(Constants.AS_WEB_CNAME).equals(cname);
    }

    private Map<String, Object> convertJsonToMap(String json) throws IOException {
        ObjectMapper mapper = new ObjectMapper();

        return mapper.readValue(json, new TypeReference<Map<String, Object>>() {});
    }

    public boolean verifyAccount(String cname, String password) {
        MemberDto memberDto = new MemberDto(cname, password, null, null, null, null, null, null, -1);
        this.authTarget = this.memberMapper.getOne(memberDto);
        return this.authTarget != null;
    }

    public String createTicket(String from, String to, Key sk, IvParameterSpec iv) throws JsonProcessingException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        ObjectMapper mapper = new ObjectMapper();
        CryptoHelper cryptoHelper = CryptoHelper.getInstance();
        String institution = this.authTarget.getInstitute();

        Map<String, String> time = new HashMap<String, String>();
        time.put(Constants.AS_WEB_FROM, from);
        time.put(Constants.AS_WEB_TO, to);

        Map<String, Object> map = new HashMap<>();
        map.put(Constants.AS_WEB_CNAME, this.authTarget.getId());
//        map.put(Constants.AS_WEB_INSTITUTE, institution);
        map.put(Constants.AS_WEB_TIME, time);

        String ticketPlain = mapper.writeValueAsString(map);
        return cryptoHelper.encryptWithAes(ticketPlain, sk, iv);
    }

    public AsAppResponse createAuthResponse(String ticket, String sk, String iv) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Calendar calendar = Calendar.getInstance();
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String ts = dateFormat.format(calendar.getTime());
        ObjectMapper mapper = new ObjectMapper();
        CryptoHelper cryptoHelper = CryptoHelper.getInstance();

        // sk and iv should be encrypted with the WI's public key.

        Map<String, Object> body = new HashMap<String, Object>();
        body.put(Constants.AS_WEB_TICKET, ticket);
        body.put(Constants.AS_WEB_SK, sk);
        body.put(Constants.AS_WEB_IV, iv);
        body.put(Constants.AS_WEB_TIMESTAMP, ts);

        FileReader privateKeyReader = new FileReader("AS-KeyPair/AS-PrivateKey.pem");
        PrivateKey privateKey = cryptoHelper.restorePrivateKeyFromPem(privateKeyReader);
        String signature = cryptoHelper.getSignature(mapper.writeValueAsString(body).getBytes(), privateKey);

        return new AsAppResponse(body, signature);
    }

    @SneakyThrows
    public AsAppResponse createVerifyResponse(String ticket, String cname, SecretDto secretDto) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, IOException {
        boolean verify = this.verifyTicket(ticket, cname, secretDto);
        Map<String, Object> body = new HashMap<>();
        CryptoHelper cryptoHelper = CryptoHelper.getInstance();
        ObjectMapper mapper = new ObjectMapper();
        PublicKey publicKey = cryptoHelper.restorePublicKeyFromPem(new FileReader("AS-KeyPair/AS-PublicKey.pem"));
        String pemPublicKey = cryptoHelper.convertPublicKeyToPem(publicKey);

        body.put("verify", verify);
        body.put("cpk", pemPublicKey);
        FileReader privateKeyReader = new FileReader("AS-KeyPair/AS-PrivateKey.pem");
        PrivateKey privateKey = cryptoHelper.restorePrivateKeyFromPem(privateKeyReader);
        String signature = cryptoHelper.getSignature(mapper.writeValueAsString(body).getBytes(), privateKey);

        return new AsAppResponse(body, signature);
    }

    public AsAppResponse createSimpleReponse(String msg) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Calendar calendar = Calendar.getInstance();
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String ts = dateFormat.format(calendar.getTime());
        ObjectMapper mapper = new ObjectMapper();
        CryptoHelper cryptoHelper = CryptoHelper.getInstance();

        Map<String, Object> body = new HashMap<String, Object>();
        body.put(Constants.AS_WEB_RESULT, msg);
        body.put(Constants.AS_WEB_TIMESTAMP, ts);

//        logger.info(new File("AS-KeyPair/AS-PrivateKey.pem").exists() + "");
        FileReader privateKeyReader = new FileReader("AS-KeyPair/AS-PrivateKey.pem");
        PrivateKey privateKey = cryptoHelper.restorePrivateKeyFromPem(privateKeyReader);
        String signature = cryptoHelper.getSignature(mapper.writeValueAsString(body).getBytes(), privateKey);

        return new AsAppResponse(body, signature);
    }

    public void createAccount(MemberDto memberDto) {
        this.memberMapper.insertOne(memberDto);
    }
}
