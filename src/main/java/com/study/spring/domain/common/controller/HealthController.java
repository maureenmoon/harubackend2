package com.study.spring.domain.common.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class HealthController {
    
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "OK");
        response.put("message", "Spring Boot application is running");
        response.put("timestamp", System.currentTimeMillis());
        response.put("cors", "enabled");
        response.put("security", "configured");
        return ResponseEntity.ok(response);
    }
    
    // Debug endpoint to check cookies
    @GetMapping("/debug/cookies")
    public ResponseEntity<Map<String, Object>> debugCookies(HttpServletRequest request) {
        Map<String, Object> response = new HashMap<>();
        Map<String, String> cookies = new HashMap<>();
        
        Cookie[] requestCookies = request.getCookies();
        if (requestCookies != null) {
            for (Cookie cookie : requestCookies) {
                cookies.put(cookie.getName(), cookie.getValue());
            }
        }
        
        response.put("cookies", cookies);
        response.put("sessionId", request.getSession(false) != null ? request.getSession().getId() : "no session");
        response.put("timestamp", System.currentTimeMillis());
        
        return ResponseEntity.ok(response);
    }
}