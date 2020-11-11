package ac.kr.korea.sans.as.controller;

import ac.kr.korea.sans.as.constant.Constants;
import ac.kr.korea.sans.as.dto.MemberDto;
import ac.kr.korea.sans.as.dto.RequestDto;
import ac.kr.korea.sans.as.dto.SecretDto;
import ac.kr.korea.sans.as.restresponse.AsAppResponse;
import ac.kr.korea.sans.as.restresponse.AsErrorResponse;
import ac.kr.korea.sans.as.service.AuthenticationService;
import ac.kr.korea.sans.as.util.CryptoHelper;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.Base64Utils;
import org.springframework.web.bind.annotation.*;

import javax.annotation.PostConstruct;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
//import sun.misc.IOUtils;
//import sun.nio.ch.IOUtil;


@CrossOrigin("*")
@RestController
public class AsAppController {
    private static final Logger logger = LoggerFactory.getLogger(AsAppController.class);
    private static BouncyCastleProvider bouncyCastleProvider;
    public static final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

    static {
        bouncyCastleProvider = BOUNCY_CASTLE_PROVIDER;
    }

    @Autowired private AuthenticationService authService;

    @PostConstruct
    public void init() {

    }

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public AsAppResponse home() throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        return this.authService.createSimpleReponse("hello, world");
    }

    @RequestMapping(value = "/sign-up/process", method = RequestMethod.POST)
    public AsAppResponse signUp(@RequestBody Map<String, String> json) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        logger.info("signUp");
        try {
            MemberDto memberDto = MemberDto.convertJsonToDto(json);
            this.authService.createAccount(memberDto);
        } catch (Exception e) {
            e.printStackTrace();
            throw new AsErrorResponse("sign up failure");
        }
        return this.authService.createSimpleReponse("success");
    }

    @RequestMapping(value="/get-as-publickey", method=RequestMethod.GET)
    public AsAppResponse getPublicKey() throws IOException, CertificateException, SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        CryptoHelper cryptoHelper = CryptoHelper.getInstance();
        X509Certificate cert = cryptoHelper.getX509Certificate("AS-KeyPair/AS-Cert.der");

        return this.authService.createSimpleReponse(Base64Utils.encodeToString(cert.getEncoded()));
    }


    @RequestMapping(value = "/do-auth", method = RequestMethod.POST)
    public AsAppResponse doAuth(@RequestBody Map<String, Object> json, HttpServletRequest request) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, JsonProcessingException, Exception, BadPaddingException {
        Map<String, Object> body = (Map<String, Object>) json.get(Constants.AS_WEB_BODY);
        RequestDto requestDto = RequestDto.parseJson(json);
        CryptoHelper cryptoHelper = CryptoHelper.getInstance();

        if (!this.authService.verifySignature(body, requestDto.getSignature())) {
            throw new AsErrorResponse("invalid signature");
        }

        if (!this.authService.verifyAccount(requestDto.getCname(), requestDto.getPassword())) {
            throw new AsErrorResponse("authentication failure");
        }

        SecretKey sk = cryptoHelper.generateAesKey();
        IvParameterSpec iv = cryptoHelper.generateIv();

        String ticket = this.authService.createTicket(requestDto.getFrom(), requestDto.getTo(), sk, iv);
        String key = this.getKeyForSecretKeyMap(requestDto.getCname(), ticket);

        Constants.GLOBAL_SECRETKEY_MAP.put(key, new SecretDto(sk, iv));

        return this.authService.createAuthResponse(
                ticket,
                Base64Utils.encodeToString(sk.getEncoded()),
                Base64Utils.encodeToString(iv.getIV()));

    }

    @RequestMapping(value="/verify", method=RequestMethod.POST)
    public AsAppResponse verify(@RequestBody Map<String, Object> json) throws InvalidKeySpecException, IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        Map<String, Object> body = (Map<String, Object>) json.get(Constants.AS_WEB_BODY);
        String signature = (String) json.get(Constants.AS_WEB_SIGNATURE);

        if (!this.authService.verifySignature(body, signature)) {
            throw new AsErrorResponse("invalid signature");
        }

        String cname = (String) body.get(Constants.AS_WEB_CNAME);
        String ticket = (String) body.get(Constants.AS_WEB_TICKET);
        String key = this.getKeyForSecretKeyMap(cname, ticket);
        SecretDto secretDto = Constants.GLOBAL_SECRETKEY_MAP.get(key);

        return this.authService.createVerifyResponse(ticket, cname, secretDto);
    }

    private String getKeyForSecretKeyMap(String cname, String ticket) throws JsonProcessingException {
        Map<String, String> keyMap = new HashMap<>();
        keyMap.put("cname", cname);
        keyMap.put("ticket", ticket);
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.writeValueAsString(keyMap);
    }
}




