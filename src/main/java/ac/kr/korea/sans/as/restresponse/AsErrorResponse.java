package ac.kr.korea.sans.as.restresponse;

public class AsErrorResponse extends RuntimeException {
    public AsErrorResponse(String msg) {
        super(msg);
    }
}
