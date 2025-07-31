package com.study.spring.domain.member.repository;

import com.study.spring.domain.member.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {
    Optional<Member> findByEmail(String email);
    Optional<Member> findByNickname(String nickname);
    
    //이메일중복
    boolean existsByEmail(String email);
    //닉네임중복
    boolean existsByNickname(String nickname);
    
    List<Member> findByNicknameContainingIgnoreCaseOrEmailContainingIgnoreCase(String nickname, String email);
    Optional<Member> findByNameIgnoreCaseAndEmailIgnoreCase(String name, String email);
    
    //Allows lookup for refresh-based authentication
    Optional<Member> findByRefreshToken(String refreshToken);
} 