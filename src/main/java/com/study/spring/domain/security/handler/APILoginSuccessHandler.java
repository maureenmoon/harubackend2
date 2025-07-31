package com.study.spring.domain.security.handler;

import com.study.spring.domain.member.entity.Member;
import com.study.spring.domain.member.repository.MemberRepository;
import com.study.spring.domain.security.util.JWTUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
public class APILoginSuccessHandler implements AuthenticationSuccessHandler {

	private final JWTUtil jwtUtil;
	private final MemberRepository memberRepository;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {

		log.info("Login success: {}", authentication.getName());

		// 인증된 사용자 객체 추출
		Member member = (Member) authentication.getPrincipal();

		// JWT Claim 정보 구성
		Map<String, Object> claims = new HashMap<>();
		claims.put("memberId", member.getId()); // other API needs member's id
		claims.put("email", member.getEmail());
		claims.put("nickname", member.getNickname());
		claims.put("roles", List.of("ROLE_" + member.getRole())); // 🔥 this is the fix!

		// 토큰 생성 (유효시간: 60분)
		String accessToken = jwtUtil.generateToken(claims, 60);
		String refreshToken = jwtUtil.generateRefreshToken(claims, 7); // 7 days validity

		// refresh token to DB
		member.updateRefreshToken(refreshToken); // Add a setter or toBuilder()
		memberRepository.save(member); // Inject repository if needed

		// JSON 형식으로 토큰 응답
		response.setContentType("application/json;charset=UTF-8");

		String json = String.format("{\"accessToken\": \"%s\", \"refreshToken\": \"%s\"}", accessToken, refreshToken);
		System.out.println("🔐 Login response: " + json);
		response.getWriter().write(json);

	}
}
