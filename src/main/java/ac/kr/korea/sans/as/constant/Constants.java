package ac.kr.korea.sans.as.constant;

import ac.kr.korea.sans.as.dto.SecretDto;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class Constants {

    public static final String AS_WEB_FIRST_NAME = "firstName";
    public static final String AS_WEB_LAST_NAME = "lastName";
    public static final String AS_WEB_COUNTRY_CODE = "countryCode";
    public static final String AS_WEB_PUB = "pub";
    public static final String AS_WEB_RESULT = "result";
    public static final String AS_WEB_CPK = "cpk";
    public static final String AS_WEB_CNAME = "cname";
    public static final String AS_WEB_PASSWORD = "password";
    public static final String AS_WEB_INSTITUTE = "institute";
    public static final String AS_WEB_TIME = "time";
    public static final String AS_WEB_FROM = "from";
    public static final String AS_WEB_TO = "to";
    public static final String AS_WEB_SK = "sk";
    public static final String AS_WEB_TICKET = "ticket";
    public static final String AS_WEB_TIMESTAMP = "ts";
    public static final String AS_WEB_IV = "iv";
    public static final String AS_WEB_SIGNATURE = "signature";
    public static final String AS_WEB_BODY = "body";
    public static final String AS_WEB_DATA = "data";
    public static final String URL_GET_CERT = "/get-cert";
    public static Map<String, SecretDto> GLOBAL_SECRETKEY_MAP;
    public static String CA_DOMAIN;
    public static String CDM_DOMAIN;
    public static String TYPE_PKI;

    @Value("${ca.domain}")
    public void setCaDomain(String url) {CA_DOMAIN = url;}

    @Value("${cdm.domain}")
    public void setCdmDomain(String url) {CDM_DOMAIN = url;}

    @Value("${publickey.type}")
    public void setTypePki(String type) {TYPE_PKI = type;}
}
