package ac.kr.korea.sans.as.dao;

import java.util.List;

import ac.kr.korea.sans.as.dto.MemberDto;
import org.springframework.stereotype.Repository;

@Repository
public interface MemberMapper {
	public MemberDto getOne(MemberDto member);
	public List<MemberDto> getAll();
	public void insertOne(MemberDto member);
}
