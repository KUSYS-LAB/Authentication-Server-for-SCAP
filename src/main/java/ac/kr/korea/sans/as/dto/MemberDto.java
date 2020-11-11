package ac.kr.korea.sans.as.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class MemberDto {
	private String id;
	private String password;
	private String firstNameEn;
	private String lastNameEn;
	private String firstNameKo;
	private String lastNameKo;
	private String countryCode;
	private String institute;
	private int typeCode;


	public static MemberDto convertJsonToDto(Map<String, String> json) {
		MemberDto memberDto = new MemberDto();

		memberDto.setId(json.get("id"));
		memberDto.setPassword(json.get("password"));
		memberDto.setFirstNameEn(json.get("firstNameEn"));
		memberDto.setLastNameEn(json.get("lastNameEn"));
		memberDto.setFirstNameKo(json.get("firstNameKo"));
		memberDto.setLastNameKo(json.get("lastNameKo"));
		memberDto.setCountryCode(json.get("countryCode"));
		memberDto.setInstitute(json.get("institute"));
		memberDto.setTypeCode(Integer.parseInt(json.get("typeCode")));

		return memberDto;
	}
}
