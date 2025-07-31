package com.study.spring.domain.security.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.study.spring.domain.security.handler.CustomAccessDeniedHandler;
import com.study.spring.domain.security.util.JWTCheckFilter;
import com.study.spring.domain.security.util.JWTUtil;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {
	@Autowired
    private JWTUtil jwtUtil;
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> {}) // Use global CORS configuration
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                // Only truly public endpoints need permitAll()
                .requestMatchers(
                    "/api/members/login", 
                    "/api/members/multipart", 
                    "/api/members/check-email",
                    "/api/members/check-nickname", 
                    "/api/members/search-nickname",
                    "/api/members/reset-password", 
                    "/api/members/refresh", 
                    "/api/members/logout",
                    "/api/members/test-cookies", 
                    "/api/members/recommended-calories", 
                    "/api/health",
                    "/api/members/me/profile-image",  // Allow profile image updates
                    "/api/members/upload-image", // Allow general image upload with processing
                    "/api/members/me/upload-profile-image", // Allow enhanced profile image upload
                    "/api/members/me/recommended-calories-calculation", // Allow recommended calories calculation
                    "/images/**"  // Allow access to uploaded images
                ).permitAll()
                // All other requests need authentication
                .anyRequest().authenticated()
            )
            .addFilterBefore(new JWTCheckFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling(ex -> ex.accessDeniedHandler(new CustomAccessDeniedHandler()));
        
        return http.build();
    }
}