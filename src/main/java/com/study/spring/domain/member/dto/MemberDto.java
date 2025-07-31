package com.study.spring.domain.member.dto;

import com.study.spring.domain.member.entity.ActivityLevel;
import com.study.spring.domain.member.entity.Gender;
import com.study.spring.domain.member.entity.Member;
import com.study.spring.domain.member.entity.Role;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDate;

import org.springframework.web.multipart.MultipartFile;

public class MemberDto {
    
    @Getter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class LoginRequest {
        private String nickname;
        private String password;
        
        @Override
        public String toString() {
            return "LoginRequest{" +
                    "nickname='" + nickname + '\'' +
                    ", password='" + (password != null ? "***" : "null") + '\'' +
                    '}';
        }
    }
    
    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Setter
    @Builder
    public static class MultipartRequest {
        private String email;
        private String password;
        private String nickname;
        private String name;
        private LocalDate birthAt;
        private Gender gender;
        private Float height;
        private Float weight;
        private ActivityLevel activityLevel;
//        private String role;
//        private MultipartFile profileImage;
        
    }

    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Builder
    public static class Request {
        private String email;
        private String password;
        private String nickname;
        private String name;
        private LocalDate birthAt;
        private Gender gender;
        private Float height;
        private Float weight;
        private ActivityLevel activityLevel;
        
        @Override
        public String toString() {
            return "Request{" +
                    "email='" + email + '\'' +
                    ", nickname='" + nickname + '\'' +
                    ", name='" + name + '\'' +
                    ", birthAt=" + birthAt +
                    ", gender=" + gender +
                    ", height=" + height +
                    ", weight=" + weight +
                    ", activityLevel=" + activityLevel +
                    '}';
        }
    }
    
    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Builder
    public static class ProfileUpdateRequest {
        private String email;
        private String nickname;
        private String name;
        private LocalDate birthAt;
        private Gender gender;
        private Float height;
        private Float weight;
        private ActivityLevel activityLevel;
        
        @Override
        public String toString() {
            return "ProfileUpdateRequest{" +
                    "email='" + email + '\'' +
                    ", nickname='" + nickname + '\'' +
                    ", name='" + name + '\'' +
                    ", birthAt=" + birthAt +
                    ", gender=" + gender +
                    ", height=" + height +
                    ", weight=" + weight +
                    ", activityLevel=" + activityLevel +
                    '}';
        }
    }

    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Builder
    public static class Response {
        private Long id;
        private String email;
        private String nickname;
        private String name;
        private LocalDate birthAt;
        private Gender gender;
        private Float height;
        private Float weight;
        private ActivityLevel activityLevel;
        private String profileImageUrl;
        private Role role;
        private Integer recommendedCalories;

        public static Response from(Member member) {
            return Response.builder()
                    .id(member.getId())
                    .email(member.getEmail())
                    .nickname(member.getNickname())
                    .name(member.getName())
                    .birthAt(member.getBirthAt())
                    .gender(member.getGender())
//                    .gender(member.getGender() != null ? member.getGender().name() : null)
                    .height(member.getHeight())
                    .weight(member.getWeight())
                    .activityLevel(member.getActivityLevel())
                    .profileImageUrl(member.getProfileImageUrl())
                    .role(member.getRole())
                    .recommendedCalories(member.calculateRecommendedCalories())
                    .build();
        }
    }
    
    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class LoginResponse {
        private String accessToken;
        private String refreshToken;
    }
} 