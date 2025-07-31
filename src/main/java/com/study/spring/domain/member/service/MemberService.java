package com.study.spring.domain.member.service;

import com.study.spring.domain.member.dto.MemberDto;
import com.study.spring.domain.member.dto.MemberDto.MultipartRequest;
import com.study.spring.domain.member.entity.Member;
import com.study.spring.domain.member.entity.Role;
import com.study.spring.domain.member.repository.MemberRepository;
import com.study.spring.domain.member.util.FileUploadUtil;
import com.study.spring.domain.security.exception.CustomJWTException;
import com.study.spring.domain.security.util.JWTUtil;
import com.study.spring.domain.security.util.CookieUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import com.fasterxml.jackson.databind.ObjectMapper;


@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class MemberService {
    private final MemberRepository memberRepository;
    private final FileUploadUtil fileUploadUtil;
    private final JWTUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    private final CookieUtil cookieUtil;
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    	@Transactional
    public MemberDto.Response createMemberWithImage(MemberDto.MultipartRequest request, MultipartFile profileImage) {
    	// 이메일 중복 확인
       if (memberRepository.existsByEmail(request.getEmail())) {
        throw new ResponseStatusException(HttpStatus.CONFLICT, "이미 존재하는 이메일입니다.");
       }
    
	    // 닉네임 중복 확인
	    if (memberRepository.existsByNickname(request.getNickname())) {
	        throw new ResponseStatusException(HttpStatus.CONFLICT, "이미 존재하는 닉네임입니다.");
	    }
	    
	    // 이미지 저장
	    String profileImageUrl = null;
	    
	    if (profileImage != null && !profileImage.isEmpty()) {
	        profileImageUrl = fileUploadUtil.saveFile(profileImage); // <- save image
	    }
	    
	    System.out.println("프로필 이미지 업로드 완료: " + profileImageUrl);
	      
	    // Member 엔티티 생성 (편의 메서드 사용)
	        Member member = Member.createMember()
	                .email(request.getEmail())
	                //.password(request.getPassword()) // 실제로는 암호화 필요
	                .password(passwordEncoder.encode(request.getPassword())) //암호화
	                .nickname(request.getNickname())
	                .name(request.getName())
	                .birthAt(request.getBirthAt())
	                .gender(request.getGender())
	                .height(request.getHeight())
	                .weight(request.getWeight())
	                .activityLevel(request.getActivityLevel())
	                .profileImageUrl(profileImageUrl)
	                .role(Role.USER) //set default role
	                .build();
	        
        return MemberDto.Response.from(memberRepository.save(member));
    }

    public MemberDto.Response getMember(Long id) {
        Member member = memberRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "회원을 찾을 수 없습니다."));
        
        return MemberDto.Response.from(member);
    }

    public MemberDto.Response getMemberByEmail(String email) {
        Member member = memberRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "회원을 찾을 수 없습니다."));
        
        return MemberDto.Response.from(member);
    }

    public MemberDto.Response getMemberByNickname(String nickname) {
        Member member = memberRepository.findByNickname(nickname)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "회원을 찾을 수 없습니다."));
        
        return MemberDto.Response.from(member);
    }

//    public MemberDto.Response authenticateByNickname(String nickname, String password) {
//        try {
//            Member member = memberRepository.findByNickname(nickname)
//                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "회원을 찾을 수 없습니다."));
//
//            // Debug log
//            System.out.println("입력된 비밀번호: " + password);
//            System.out.println("DB 비밀번호: " + member.getPassword());
//
////            if (!member.getPassword().equals(password)) {
//            if (!passwordEncoder.matches(password, member.getPassword())) {  
//                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "비밀번호가 일치하지 않습니다.");
//            }
//
//            return MemberDto.Response.from(member);
//        } catch (Exception e) {
//            e.printStackTrace();  // This will print the actual cause to the server logs
//            throw e;  // Rethrow to preserve behavior
//        }
//    }
    public void authenticateByNickname(String nickname, String password, HttpServletResponse response) {
        System.out.println("🔧 AUTH: Starting authentication for nickname: " + nickname);
        
        Member member = memberRepository.findByNickname(nickname)
            .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));

        System.out.println("🔧 AUTH: Found member: " + member.getNickname() + " (ID: " + member.getId() + ")");

        if (!passwordEncoder.matches(password, member.getPassword())) {
            System.out.println("❌ AUTH: Password mismatch for user: " + nickname);
            throw new RuntimeException("비밀번호가 틀렸습니다.");
        }

        System.out.println("✅ AUTH: Password verified successfully");

        // JWT claim
        Map<String, Object> claims = new HashMap<>();
        claims.put("memberId", member.getId());
        claims.put("email", member.getEmail());
        claims.put("nickname", member.getNickname());
        claims.put("roles", List.of("ROLE_" + member.getRole().name()));
        
        System.out.println("🔧 AUTH: Claims prepared: " + claims);
        
        try {
            // Token 생성
            String accessToken = jwtUtil.generateToken(claims, 15);  // 15 minutes (reduced from 60)
            String refreshToken = jwtUtil.generateRefreshToken(claims, 7); // 7 days
            
            System.out.println("🔧 AUTH: Access token length: " + (accessToken != null ? accessToken.length() : "NULL"));
            System.out.println("🔧 AUTH: Refresh token length: " + (refreshToken != null ? refreshToken.length() : "NULL"));
            
            // Debug logging to verify tokens are different
            System.out.println("🔐 Access Token: " + (accessToken != null ? accessToken.substring(0, Math.min(20, accessToken.length())) + "..." : "NULL"));
            System.out.println("🔄 Refresh Token: " + (refreshToken != null ? refreshToken.substring(0, Math.min(20, refreshToken.length())) + "..." : "NULL"));
            System.out.println("✅ Tokens are different: " + (accessToken != null && refreshToken != null && !accessToken.equals(refreshToken)));
            
            // Calculate recommended calories
            int recommendedCalories = member.calculateRecommendedCalories();
            System.out.println("🔧 AUTH: Calculated recommended calories: " + recommendedCalories);
            
         // Set cookies instead of returning tokens
            cookieUtil.setHttpOnlyCookie(response, "accessToken", accessToken, 15 * 60);
            System.out.println("🔧 DEBUG: After accessToken - Headers: " + response.getHeaderNames());

            cookieUtil.setHttpOnlyCookie(response, "refreshToken", refreshToken, 7 * 24 * 60 * 60);
            System.out.println("🔧 DEBUG: After refreshToken - Headers: " + response.getHeaderNames());

            cookieUtil.setHttpOnlyCookie(response, "recommendedCalories", String.valueOf(recommendedCalories), 7 * 24 * 60 * 60);
            System.out.println("🔧 DEBUG: After recommendedCalories - Headers: " + response.getHeaderNames());
            
            // Set userData cookie with profile image URL
            String userDataJson = createUserDataJson(member, recommendedCalories);
            cookieUtil.setUserDataCookie(response, userDataJson);
            System.out.println("🔧 DEBUG: After userData - Headers: " + response.getHeaderNames());
            
            System.out.println("✅ AUTH: Cookies set successfully (including userData with profile image)");
            
            // refreshToken 저장
            member.updateRefreshToken(refreshToken);
            memberRepository.save(member);
            
            System.out.println("✅ AUTH: Authentication completed successfully");
            
        } catch (Exception e) {
            System.out.println("❌ AUTH: Error during token generation: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    @Transactional
    public MemberDto.Response updateMemberWithImage(Long id, MemberDto.MultipartRequest request, MultipartFile imageFile) {
        Member member = memberRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "회원을 찾을 수 없습니다."));

        // 이메일 변경 시 중복 확인
        if (!member.getEmail().equals(request.getEmail()) && memberRepository.existsByEmail(request.getEmail())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "이미 존재하는 이메일입니다.");
        }
        
        // 닉네임 변경 시 중복 확인
        if (!member.getNickname().equals(request.getNickname()) && memberRepository.existsByNickname(request.getNickname())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "이미 존재하는 닉네임입니다.");
        }
        
        String imageUrl = member.getProfileImageUrl();//keep exisiting if no new image
        
        if (imageFile != null && !imageFile.isEmpty()) {
        	imageUrl = fileUploadUtil.saveFile(imageFile);
        }

        System.out.println("프로필 이미지 업로드 완료: " + imageUrl);
        
       // Member 엔티티 업데이트 (편의 메서드 사용)
       Member updateMember = member.toBuilder()
       .email(request.getEmail())
       //.password(request.getPassword()) // 실제로는 암호화 필요
       .password(passwordEncoder.encode(request.getPassword())) //암호화
       .nickname(request.getNickname())
       .name(request.getName())
       .birthAt(request.getBirthAt())
       .gender(request.getGender())
       .height(request.getHeight())
       .weight(request.getWeight())
       .activityLevel(request.getActivityLevel())
       .profileImageUrl(imageUrl)
       .build();

		//Member updatedMember = memberRepository.save(member);
		return MemberDto.Response.from(memberRepository.save(updateMember));
}

    @Transactional
    public MemberDto.Response updateMember(Long id, MemberDto.ProfileUpdateRequest request) {
        System.out.println("🔧 Service: Updating member ID: " + id);
        System.out.println("🔧 Service: Request data: " + request);
        
        // Debug: Check if request fields are null
        System.out.println("🔧 Service: Email from request: " + request.getEmail());
        System.out.println("🔧 Service: Nickname from request: " + request.getNickname());
        System.out.println("🔧 Service: Name from request: " + request.getName());
        System.out.println("🔧 Service: BirthAt from request: " + request.getBirthAt());
        System.out.println("🔧 Service: Gender from request: " + request.getGender());
        System.out.println("🔧 Service: Height from request: " + request.getHeight());
        System.out.println("🔧 Service: Weight from request: " + request.getWeight());
        System.out.println("🔧 Service: ActivityLevel from request: " + request.getActivityLevel());
        
        Member member = memberRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "회원을 찾을 수 없습니다."));

        System.out.println("🔧 Service: Found member: " + member.getNickname());
        System.out.println("🔧 Service: Current member email: " + member.getEmail());

        // 이메일 변경 시 중복 확인
        if (request.getEmail() != null && !member.getEmail().equals(request.getEmail()) && memberRepository.existsByEmail(request.getEmail())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "이미 존재하는 이메일입니다.");
        }
        
        // 닉네임 변경 시 중복 확인
        if (request.getNickname() != null && !member.getNickname().equals(request.getNickname()) && memberRepository.existsByNickname(request.getNickname())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "이미 존재하는 닉네임입니다.");
        }
        
        // Member 엔티티 업데이트 - 비밀번호 제외
        Member updatedMember = member.toBuilder()
                .email(request.getEmail() != null ? request.getEmail() : member.getEmail())
                .nickname(request.getNickname() != null ? request.getNickname() : member.getNickname())
                .name(request.getName() != null ? request.getName() : member.getName())
                .birthAt(request.getBirthAt() != null ? request.getBirthAt() : member.getBirthAt())
                .gender(request.getGender() != null ? request.getGender() : member.getGender())
                .height(request.getHeight() != null ? request.getHeight() : member.getHeight())
                .weight(request.getWeight() != null ? request.getWeight() : member.getWeight())
                .activityLevel(request.getActivityLevel() != null ? request.getActivityLevel() : member.getActivityLevel())
                .build();
        
        System.out.println("🔧 Service: Profile updated (password excluded from general profile updates)");
        System.out.println("🔧 Service: Updated member email: " + updatedMember.getEmail());
        System.out.println("🔧 Service: Updated member nickname: " + updatedMember.getNickname());

        MemberDto.Response response = MemberDto.Response.from(memberRepository.save(updatedMember));
        System.out.println("✅ Service: Profile update completed successfully");
        return response;
    }

    @Transactional
    public void updatePassword(Long memberId, String newPassword) {
        Member member = memberRepository.findById(memberId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "존재하지 않는 회원입니다."));

        // toBuilder() 사용으로 통일
        Member updatedMember = member.toBuilder()
                //.password(newPassword) // 실제로는 암호화 필요
                .password(passwordEncoder.encode(newPassword)) //암호화
                .build();

        memberRepository.save(updatedMember);
    }

    @Transactional
    public void updateProfileImage(Long id, MultipartFile profileImage) {
        Member member = memberRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "존재하지 않는 회원입니다."));

        String imageUrl = fileUploadUtil.saveFile(profileImage);
        
        // toBuilder() 사용으로 통일
        Member updatedMember = member.toBuilder()
                .profileImageUrl(imageUrl)
                .build();

        memberRepository.save(updatedMember);
    }

    @Transactional
    public void updateProfileImageUrl(Long memberId, String imageUrl, HttpServletRequest request, HttpServletResponse response) {
        Member member = memberRepository.findById(memberId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "존재하지 않는 회원입니다."));

        // toBuilder() 사용으로 통일
        Member updatedMember = member.toBuilder()
                .profileImageUrl(imageUrl)
                .build();

        memberRepository.save(updatedMember);
        
        // Update userData cookie with new profile image URL
        if (request != null && response != null) {
            cookieUtil.updateProfileImageInCookie(request, response, imageUrl);
        }
    }

    @Transactional
    public void deleteMember(Long id) {
        Member member = memberRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "회원을 찾을 수 없습니다."));

        memberRepository.delete(member);
    }

    // 추가 편의 메서드들
    
	// 이메일 중복 확인
    public boolean existsByEmail(String email) {
        return memberRepository.existsByEmail(email);
    }
	// 닉네임 중복 확인
    public boolean existsByNickname(String nickname) {
        return memberRepository.existsByNickname(nickname);
    }
	// 멤버 찾기???
    public List<MemberDto.Response> searchMembers(String query) {
        List<Member> members = memberRepository.findByNicknameContainingIgnoreCaseOrEmailContainingIgnoreCase(query, query);
        return members.stream().map(MemberDto.Response::from).toList();
    }
    // 닉네임 찾기
    public Optional<String> findNicknameByNameAndEmail(String name, String email) {
        return memberRepository.findByNameIgnoreCaseAndEmailIgnoreCase(name.trim(), email.trim()).map(Member::getNickname);
    }
    //비밀번호 변경
    public boolean requestPasswordReset(String email) {
        Optional<Member> member = memberRepository.findByEmail(email);
        if (member.isPresent()) {
            // TODO: Implement email sending logic here
            return true;
        } else {
            return false;
        }
    }
    
    //refresh token :Validates the refresh token, and if valid, issues a new access token
    @Transactional
    public ResponseEntity<?> refreshAccessToken(String refreshToken) {
        Optional<Member> result = memberRepository.findByRefreshToken(refreshToken);

        if (result.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
        }

        Member member = result.get();

        try {
            jwtUtil.validateToken(refreshToken);

            Map<String, Object> claims = new HashMap<>();
            claims.put("email", member.getEmail());
            claims.put("nickname", member.getNickname());
            claims.put("roles", List.of("ROLE_" + member.getRole().name()));

            String newAccessToken = jwtUtil.generateToken(claims, 60); 
            return ResponseEntity.ok(Map.of("accessToken", newAccessToken));

        } catch (CustomJWTException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Refresh token expired or invalid");
        }
    }
    
    //img upload to supabase
    @Transactional
    public void updatePhotoByEmail(String email, String photoUrl) {
        System.out.println("🔧 SERVICE: Updating photo for email: " + email);
        System.out.println(" SERVICE: Photo URL: " + photoUrl);
        
        Member member = memberRepository.findByEmail(email)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "회원을 찾을 수 없습니다."));

        System.out.println("🔧 SERVICE: Found member: " + member.getNickname());
        System.out.println("🔧 SERVICE: Current profileImageUrl: " + member.getProfileImageUrl());

        // Member 엔티티 업데이트 (편의 메서드 사용)
        Member updatedMember = member.toBuilder()
            .profileImageUrl(photoUrl)
            .build();

        System.out.println("프로필 이미지 업로드 완료: " + photoUrl);
        
        memberRepository.save(updatedMember);
        System.out.println("✅ SERVICE: Profile image update completed successfully");
    }



    /**
     * Create userData JSON string with profile image URL
     * @param member Member entity
     * @param recommendedCalories Recommended calories
     * @return JSON string containing user data
     */
    public String createUserDataJson(Member member, int recommendedCalories) {
        try {
            Map<String, Object> userData = new HashMap<>();
            userData.put("email", member.getEmail());
            userData.put("nickname", member.getNickname());
            userData.put("memberId", member.getId());
            userData.put("name", member.getName());
            userData.put("height", member.getHeight());
            userData.put("weight", member.getWeight());
            userData.put("activityLevel", member.getActivityLevel().name());
            userData.put("role", member.getRole().name());
            userData.put("photo", ""); // Legacy field
            userData.put("id", member.getId());
            userData.put("birthAt", member.getBirthAt());
            userData.put("gender", member.getGender().name());
            userData.put("profileImageUrl", member.getProfileImageUrl());
            userData.put("recommendedCalories", recommendedCalories);
            
            String json = objectMapper.writeValueAsString(userData);
            System.out.println("🔧 AUTH: Created userData JSON: " + json);
            return json;
        } catch (Exception e) {
            System.out.println("❌ AUTH: Failed to create userData JSON: " + e.getMessage());
            return "{}";
        }
    }
}