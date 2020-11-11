package ac.kr.korea.sans.as.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class SecretDto {
    private SecretKey sk;
    private IvParameterSpec iv;
}
