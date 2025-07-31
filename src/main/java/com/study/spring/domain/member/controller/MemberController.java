package com.study.spring.domain.member.controller;

import com.study.spring.domain.member.dto.MemberDto;
import com.study.spring.domain.email.EmailService;
import com.study.spring.domain.member.dto.ImageProcessingResult;
import com.study.spring.domain.member.entity.Member;
import com.study.spring.domain.member.repository.MemberRepository;
import com.study.spring.domain.member.service.MemberService;
import com.study.spring.domain.member.util.ImageProcessingUtil;
import com.study.spring.domain.security.config.SecurityConfig;
import com.study.spring.domain.security.exception.CustomJWTException;
import com.study.spring.domain.security.util.JWTUtil;
import com.study.spring.domain.security.util.CookieUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import java.util.Optional;
import java.util.Random;
import java.util.HashMap;
import java.time.LocalDate;
import com.study.spring.domain.member.entity.Gender;
import com.study.spring.domain.member.entity.ActivityLevel;

//@CrossOrigin(origins = "http://localhost:5173")//remove once bk&frt connection success
@RestController
@RequestMapping("/api/members")
@RequiredArgsConstructor
public class MemberController {
	
    private final MemberService memberService;
    private final MemberRepository memberRepository;
    private final JWTUtil jwtUtil;
    private final CookieUtil cookieUtil;
    private final ImageProcessingUtil imageProcessingUtil;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

     
    // 회원 가입+프로필 이미지 생성
    @PostMapping(value = "/multipart", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<MemberDto.Response> createMemberWithImage(
    		@RequestPart("data") MemberDto.MultipartRequest request,
    		@RequestPart(value="profileImage", required = false) MultipartFile profileImage) {
    	System.out.println("📥 Signup API called with email: " + request.getEmail());
    	return ResponseEntity.ok(memberService.createMemberWithImage(request, profileImage));
    }
   
    // 로그인 (닉네임 기반) - Cookie-based
    @PostMapping("/login")
    public ResponseEntity<MemberDto.Response> login(
            @RequestBody MemberDto.LoginRequest request,
            HttpServletResponse response) {
        
        System.out.println("🔧 LOGIN: Login request received for nickname: " + request.getNickname());
        System.out.println("🔧 LOGIN: Request body: " + request);
        
        try {
            System.out.println("🔧 LOGIN: Calling authenticateByNickname...");
            memberService.authenticateByNickname(request.getNickname(), request.getPassword(), response);
            System.out.println("✅ LOGIN: Authentication successful");
            
            // Return user info instead of tokens (tokens are now in cookies)
            Member member = memberRepository.findByNickname(request.getNickname())
                .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
            
            System.out.println("✅ LOGIN: Returning user info for: " + member.getNickname());
            return ResponseEntity.ok(MemberDto.Response.from(member));
        } catch (RuntimeException e) {
            System.out.println("❌ LOGIN: Authentication failed: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(null);
        } catch (Exception e) {
            System.out.println("❌ LOGIN: Unexpected error: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(null);
        }
    }

    // 로그아웃 - Cookie-based
//    @PostMapping("/logout")
//    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
//        System.out.println("🔧 LOGOUT: Logout request received");
//        
//        // 1. Clear cookies with proper domain/path matching
//        System.out.println("🔧 LOGOUT: Clearing accessToken cookie");
//        cookieUtil.clearCookie(response, "accessToken");
//        
//        System.out.println("🔧 LOGOUT: Clearing refreshToken cookie");
//        cookieUtil.clearCookie(response, "refreshToken");
//        
//        System.out.println("🔧 LOGOUT: Clearing recommendedCalories cookie");
//        cookieUtil.clearCookie(response, "recommendedCalories");
//        
//        System.out.println("🔧 LOGOUT: Clearing userData cookie");
//        cookieUtil.clearCookie(response, "userData");
//        
//        // 2. Also clear from database (invalidate refresh token)
//        Cookie[] cookies = request.getCookies();
//        if (cookies != null) {
//            for (Cookie cookie : cookies) {
//                if ("refreshToken".equals(cookie.getName())) {
//                    System.out.println("🔧 LOGOUT: Invalidating refresh token in database");
//                    // Invalidate refresh token in database
//                    memberRepository.findByRefreshToken(cookie.getValue())
//                        .ifPresent(member -> {
//                            member.updateRefreshToken(null);
//                            memberRepository.save(member);
//                            System.out.println("✅ LOGOUT: Refresh token invalidated for member ID: " + member.getId());
//                        });
//                    break;
//                }
//            }
//        }
//        
//        // 3. Set additional headers to ensure cookie clearing and prevent caching
//        response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
//        response.setHeader("Pragma", "no-cache");
//        response.setHeader("Expires", "0");
//        
//        // Add additional debugging
//        System.out.println("🔧 LOGOUT: Response headers after clearing cookies:");
//        for (String headerName : response.getHeaderNames()) {
//            System.out.println("🔧 LOGOUT: " + headerName + " = " + response.getHeader(headerName));
//        }
//        
//        System.out.println("✅ LOGOUT: Logout completed successfully");
//        return ResponseEntity.ok().build();
//    }
    
 // 로그아웃 - Stateless JWT-based
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        System.out.println("🔧 LOGOUT: Logout request received");
        
        // 1. Clear ALL possible cookies using CookieUtil
        String[] cookiesToClear = {
            "accessToken", "refreshToken", "recommendedCalories", 
            "userData", "frontendUserData", "todayCalories", 
            "todayNutrients", "mealData"
        };
        
        for (String cookieName : cookiesToClear) {
            System.out.println("�� LOGOUT: Clearing " + cookieName + " cookie");
            cookieUtil.clearCookie(response, cookieName);
        }
        
        // 2. Invalidate refresh token in database
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refreshToken".equals(cookie.getName())) {
                    System.out.println("🔧 LOGOUT: Invalidating refresh token in database");
                    memberRepository.findByRefreshToken(cookie.getValue())
                        .ifPresent(member -> {
                            member.updateRefreshToken(null);
                            memberRepository.save(member);
                            System.out.println("✅ LOGOUT: Refresh token invalidated for member ID: " + member.getId());
                        });
                    break;
                }
            }
        }
        
        // 3. Set headers to prevent caching
        response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Expires", "0");
        
        // 4. Add debugging
        System.out.println("🔧 LOGOUT: Response headers after clearing cookies:");
        for (String headerName : response.getHeaderNames()) {
            System.out.println("�� LOGOUT: " + headerName + " = " + response.getHeader(headerName));
        }
        
        System.out.println("✅ LOGOUT: Logout completed successfully");
        return ResponseEntity.ok().build();
    }
    // ID로 회원 조회
    @GetMapping("/id/{id}")
    public ResponseEntity<MemberDto.Response> getMember(@PathVariable("id") Long id) {
        return ResponseEntity.ok(memberService.getMember(id));
    }

    // 닉네임으로 회원 조회
    @GetMapping("/nickname/{nickname}")
    public ResponseEntity<MemberDto.Response> getMemberByNickname(@PathVariable("nickname") String nickname) {
        return ResponseEntity.ok(memberService.getMemberByNickname(nickname));
    }

    // 이메일로 회원 조회
    @GetMapping("/email/{email}")
    public ResponseEntity<MemberDto.Response> getMemberByEmail(@PathVariable("email") String email) {
        return ResponseEntity.ok(memberService.getMemberByEmail(email));
    }

    // 회원 정보 수정
    @PutMapping(value = "/{id}/multipart", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<MemberDto.Response> updateMemberWithImage(
//            @PathVariable("id") Long id,
            @PathVariable Long id,
            @RequestPart("data") MemberDto.MultipartRequest request,
            @RequestPart(value = "profileImage", required = false) MultipartFile profileImage) {

        return ResponseEntity.ok(memberService.updateMemberWithImage(id, request, profileImage));
    }
    
    // 비밀번호 변경(로그인-마이페이지에서)
    @PatchMapping("/{id}/password")
    public ResponseEntity<Void> updatePassword(
            @PathVariable("id") Long id,
//            @RequestParam String newPassword) {
    	  @RequestParam("newPassword") String newPassword) {  // Add explicit parameter name
        memberService.updatePassword(id, newPassword);
        return ResponseEntity.noContent().build();
    }
    
    		
    // 프로필 이미지 변경 (기존)
    @PatchMapping(value = "/{id}/profile-image", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Void> updateProfileImage(
            @PathVariable("id") Long id,
            @RequestPart("profileImage") MultipartFile profileImage) {
        memberService.updateProfileImage(id, profileImage);
        return ResponseEntity.noContent().build();
    }

    // Enhanced 프로필 이미지 업로드 (압축, 썸네일, 스마트 네이밍)
    @PostMapping(value = "/upload-image", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ImageProcessingResult> uploadImageWithProcessing(
            @RequestPart("image") MultipartFile image) {
        
        try {
            // Process image with compression, thumbnail, and smart naming
            Map<String, Object> result = imageProcessingUtil.processImage(image);
            
            if (result == null) {
                return ResponseEntity.badRequest()
                    .body(ImageProcessingResult.error("No image provided"));
            }

            // Convert to DTO
            ImageProcessingResult response = ImageProcessingResult.success(
                (String) result.get("mainImagePath"),
                (String) result.get("thumbnailPath"),
                (Long) result.get("originalSize"),
                (Long) result.get("processedSize"),
                (Long) result.get("thumbnailSize"),
                (String) result.get("timestamp"),
                (String) result.get("originalFilename")
            );

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(ImageProcessingResult.error("Image processing failed: " + e.getMessage()));
        }
    }

    // Enhanced 프로필 이미지 업로드 (인증된 사용자용)
    @PostMapping(value = "/me/upload-profile-image", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ImageProcessingResult> uploadProfileImageWithProcessing(
            @RequestPart("image") MultipartFile image,
            Authentication authentication,
            HttpServletRequest request,
            HttpServletResponse response) {
        
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ImageProcessingResult.error("Authentication required"));
        }

        try {
            Long memberId = (Long) authentication.getPrincipal();
            
            // Process image with compression, thumbnail, and smart naming
            Map<String, Object> result = imageProcessingUtil.processImage(image);
            
            if (result == null) {
                return ResponseEntity.badRequest()
                    .body(ImageProcessingResult.error("No image provided"));
            }

            // Update member's profile image URL in database
            String mainImagePath = (String) result.get("mainImagePath");
            String imageUrl = "/images/" + mainImagePath;
            memberService.updateProfileImageUrl(memberId, imageUrl, request, response);

            // Convert to DTO
            ImageProcessingResult imageResponse = ImageProcessingResult.success(
                (String) result.get("mainImagePath"),
                (String) result.get("thumbnailPath"),
                (Long) result.get("originalSize"),
                (Long) result.get("processedSize"),
                (Long) result.get("thumbnailSize"),
                (String) result.get("timestamp"),
                (String) result.get("originalFilename")
            );

            return ResponseEntity.ok(imageResponse);

        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(ImageProcessingResult.error("Image processing failed: " + e.getMessage()));
        }
    }
    // 회원 탈퇴
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteMember(@PathVariable("id") Long id) {
        memberService.deleteMember(id);
        return ResponseEntity.noContent().build();
    }

    // 이메일 중복 확인
    @GetMapping("/check-email")
    public ResponseEntity<Boolean> checkEmailExists(@RequestParam("email") String email) {
        return ResponseEntity.ok(memberService.existsByEmail(email));
    }

    // 닉네임 중복 확인
    @GetMapping("/check-nickname")
    public ResponseEntity<Boolean> checkNicknameExists(@RequestParam("nickname") String nickname) {
        return ResponseEntity.ok(memberService.existsByNickname(nickname));
    }

    // 프로필 검색
    @GetMapping("/search")
    public ResponseEntity<List<MemberDto.Response>> searchMembers(@RequestParam("query") String query) {
        return ResponseEntity.ok(memberService.searchMembers(query));
    }

    // 닉네임 찾기
    @PostMapping("/search-nickname")
    public ResponseEntity<?> searchNickname(@RequestBody Map<String, String> payload) {
        String name = payload.get("name");
        String email = payload.get("email");
        return memberService.findNicknameByNameAndEmail(name, email)
            .map(nickname -> ResponseEntity.ok(Map.of("nickname", nickname)))
            .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("message", "No user found")));
    }
    
    // 비밀번호 재설정 요청(비로그인 상태에서)
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> payload) {
        String name = payload.get("name");
        String email = payload.get("email");
        
        try {
            // Find member by name and email
            Optional<Member> memberOpt = memberRepository.findByNameAndEmail(name, email);
            
            if (memberOpt.isPresent()) {
                Member member = memberOpt.get();
                
                // Generate temporary password
                String temporaryPassword = generateTemporaryPassword();
                
                // Update member's password
                member.setPassword(passwordEncoder.encode(temporaryPassword));
                memberRepository.save(member);
                
                // Send email with temporary password
                emailService.sendPasswordResetEmail(email, name, temporaryPassword);
                
                return ResponseEntity.ok(Map.of("message", "임시 비밀번호가 이메일로 발송되었습니다."));
            } else {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("message", "해당 정보로 등록된 회원을 찾을 수 없습니다."));
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("message", "비밀번호 재설정 중 오류가 발생했습니다."));
        }
    }

    private String generateTemporaryPassword() {
        // Generate 8-character random password
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder();
        Random random = new Random();
        for (int i = 0; i < 8; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }
    //security
    @GetMapping("/me")
    public ResponseEntity<MemberDto.Response> getCurrentMember(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        
        Long memberId = (Long) authentication.getPrincipal();
        Member member = memberRepository.findById(memberId)
            .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));

        MemberDto.Response dto = MemberDto.Response.builder()
            .id(member.getId())
            .email(member.getEmail())
            .nickname(member.getNickname())
            .name(member.getName())
            .birthAt(member.getBirthAt())
            .gender(member.getGender())
            .height(member.getHeight())
            .weight(member.getWeight())
            .activityLevel(member.getActivityLevel())
//            .targetCalories(member.getTargetCalories())
            .role(member.getRole())
            .profileImageUrl(member.getProfileImageUrl())
            .build();

        return ResponseEntity.ok(dto);
    }
    //refresh token endpoint:obtain new access tokens using refresh tokens
    @PostMapping("/refresh")
    public ResponseEntity<Void> refreshToken(
            HttpServletRequest request,
            HttpServletResponse response) {
        
        // Get refresh token from cookies
        String refreshToken = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refreshToken".equals(cookie.getName())) {
                    refreshToken = cookie.getValue();
                    break;
                }
            }
        }
        
        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        
        try {
            // Validate refresh token and get member
            Optional<Member> memberOpt = memberRepository.findByRefreshToken(refreshToken);
            if (memberOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }
            
            Member member = memberOpt.get();
            
            // Generate new access token
            Map<String, Object> claims = new HashMap<>();
            claims.put("memberId", member.getId());
            claims.put("email", member.getEmail());
            claims.put("nickname", member.getNickname());
            claims.put("roles", List.of("ROLE_" + member.getRole().name()));
            
            String newAccessToken = jwtUtil.generateToken(claims, 15); // 15 minutes (updated to match login)
            
            // Recalculate recommended calories (in case member data changed)
            int recommendedCalories = member.calculateRecommendedCalories();
            System.out.println("🔧 REFRESH: Recalculated recommended calories: " + recommendedCalories);
            
            // Set new access token cookie
            cookieUtil.setHttpOnlyCookie(response, "accessToken", newAccessToken, 15 * 60); // 15 minutes
            cookieUtil.setHttpOnlyCookie(response, "recommendedCalories", String.valueOf(recommendedCalories), 7 * 24 * 60 * 60); // 7 days
            
            return ResponseEntity.ok().build();
            
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
    
    //img upload to supabase
    // Your existing endpoints will work with authentication
    @PatchMapping("/me/profile-image")
    public ResponseEntity<String> updateProfileImageWithUrl(
        @RequestBody Map<String, String> request,
        Authentication authentication,
        HttpServletRequest httpRequest,
        HttpServletResponse httpResponse
    ) {
        // This will now work with proper authentication
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        
        Long memberId = (Long) authentication.getPrincipal();
        Member member = memberRepository.findById(memberId)
            .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        
        // ✅ FIX: Use the correct field name that matches the frontend
        String photoUrl = request.get("profile_image_url");
        System.out.println("🔧 CONTROLLER: Received photoUrl: " + photoUrl);

        memberService.updatePhotoByEmail(member.getEmail(), photoUrl);
        
        // Update userData cookie with new profile image URL
        cookieUtil.updateProfileImageInCookie(httpRequest, httpResponse, photoUrl);
        
        return ResponseEntity.ok("Profile image updated successfully.");
    }

    // 현재 사용자 프로필 수정
    @PutMapping("/me")
    public ResponseEntity<MemberDto.Response> updateMyProfile(
            @RequestBody MemberDto.ProfileUpdateRequest request,
            Authentication authentication) {
        
        System.out.println("🔧 Profile update request received: " + request);
        System.out.println("🔧 Authentication principal: " + authentication.getPrincipal());
        System.out.println("🔧 Authentication principal type: " + (authentication.getPrincipal() != null ? authentication.getPrincipal().getClass().getName() : "null"));
        
        Long memberId = (Long) authentication.getPrincipal();
        System.out.println("🔧 Updating member ID: " + memberId);
        
        try {
            MemberDto.Response response = memberService.updateMember(memberId, request);
            System.out.println("✅ Profile update successful for member: " + memberId);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            System.out.println("❌ Profile update failed: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }
    
    // Alternative flexible endpoint
    @PutMapping("/me/flexible")
    public ResponseEntity<MemberDto.Response> updateMyProfileFlexible(
            @RequestBody Map<String, Object> requestMap,
            Authentication authentication) {
        
        System.out.println("🔧 FLEXIBLE: Request map: " + requestMap);
        Long memberId = (Long) authentication.getPrincipal();
        System.out.println("🔧 FLEXIBLE: Member ID: " + memberId);
        
        try {
            // Convert Map to DTO (password excluded for profile updates)
            MemberDto.ProfileUpdateRequest request = MemberDto.ProfileUpdateRequest.builder()
                .email((String) requestMap.get("email"))
                .nickname((String) requestMap.get("nickname"))
                .name((String) requestMap.get("name"))
                .birthAt(requestMap.get("birthAt") != null ? LocalDate.parse((String) requestMap.get("birthAt")) : null)
                .gender(requestMap.get("gender") != null ? Gender.valueOf((String) requestMap.get("gender")) : null)
                .height(requestMap.get("height") != null ? Float.valueOf(requestMap.get("height").toString()) : null)
                .weight(requestMap.get("weight") != null ? Float.valueOf(requestMap.get("weight").toString()) : null)
                .activityLevel(requestMap.get("activityLevel") != null ? ActivityLevel.valueOf((String) requestMap.get("activityLevel")) : null)
                .build();
            
            System.out.println("🔧 FLEXIBLE: Converted to DTO: " + request);
            MemberDto.Response response = memberService.updateMember(memberId, request);
            System.out.println("✅ FLEXIBLE: Profile update successful");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            System.out.println("❌ FLEXIBLE: Profile update failed: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }
    
    // Alternative endpoint for debugging - accepts any JSON
    @PutMapping("/me/debug")
    public ResponseEntity<String> updateMyProfileDebug(
            @RequestBody String rawRequest,
            Authentication authentication) {
        
        System.out.println("🔧 DEBUG: Raw request body: " + rawRequest);
        Long memberId = (Long) authentication.getPrincipal();
        System.out.println("🔧 DEBUG: Member ID: " + memberId);
        
        return ResponseEntity.ok("Debug endpoint reached successfully");
    }
    
    // Test endpoint to check cookies
    @GetMapping("/test-cookies")
    public ResponseEntity<String> testCookies(HttpServletRequest request) {
        StringBuilder response = new StringBuilder();
        response.append("🔍 Cookie Test Results:\n");
        
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                response.append("Cookie: ").append(cookie.getName())
                       .append(" = ").append(cookie.getValue().substring(0, Math.min(20, cookie.getValue().length())))
                       .append("...\n");
            }
        } else {
            response.append("No cookies found\n");
        }
        
        return ResponseEntity.ok(response.toString());
    }
    
    // Get recommended calories from cookies
    @GetMapping("/recommended-calories")
    public ResponseEntity<Map<String, Object>> getRecommendedCalories(HttpServletRequest request) {
        Integer recommendedCalories = cookieUtil.readRecommendedCalories(request);
        
        Map<String, Object> response = new HashMap<>();
        if (recommendedCalories != null) {
            response.put("recommendedCalories", recommendedCalories);
            response.put("message", "Recommended calories retrieved from cookies");
            System.out.println("✅ API: Returning recommended calories: " + recommendedCalories);
            return ResponseEntity.ok(response);
        } else {
            response.put("message", "Recommended calories not found in cookies");
            System.out.println("❌ API: Recommended calories not found in cookies");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        }
    }

    // Get recommended calories calculation for frontend
    @GetMapping("/me/recommended-calories-calculation")
    public ResponseEntity<Map<String, Object>> getRecommendedCaloriesCalculation(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        
        Long memberId = (Long) authentication.getPrincipal();
        Member member = memberRepository.findById(memberId)
            .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));
        
        int recommendedCalories = member.calculateRecommendedCalories();
        
        Map<String, Object> response = new HashMap<>();
        response.put("recommendedCalories", recommendedCalories);
        response.put("message", "Recommended calories calculated successfully");
        
        return ResponseEntity.ok(response);
    }

} 