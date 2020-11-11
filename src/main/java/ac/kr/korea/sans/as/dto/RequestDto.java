package ac.kr.korea.sans.as.dto;

import ac.kr.korea.sans.as.constant.Constants;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class RequestDto {
    private String cname;
    private String password;
    private String cpk;
    private String from;
    private String to;
    private String ts;
    private String signature;

    public static RequestDto parseJson(Map<String, Object> json) {
        Map<String, Object> body = (Map<String, Object>) json.get(Constants.AS_WEB_BODY);
        Map<String, String> time = (Map<String, String>) body.get(Constants.AS_WEB_TIME);

        String cname = (String) body.get(Constants.AS_WEB_CNAME);
        String password = (String) body.get(Constants.AS_WEB_PASSWORD);
        String cpk = (String) body.get(Constants.AS_WEB_CPK);
        String from = time.get(Constants.AS_WEB_FROM);
        String to = time.get(Constants.AS_WEB_TO);
        String ts = (String) body.get(Constants.AS_WEB_TIMESTAMP);
        String signature = (String) json.get(Constants.AS_WEB_SIGNATURE);

        return new RequestDto(cname, password, cpk, from, to, ts, signature);
    }
}
