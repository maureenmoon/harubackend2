package com.study.spring.domain.security.util;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

public class JWTCheckFilter extends OncePerRequestFilter {

	private static final Logger log = LoggerFactory.getLogger(JWTCheckFilter.class);
    private final JWTUtil jwtUtil;

    public JWTCheckFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String token = null;
        
        // First try to get token from cookies (preferred method)
        Cookie[] cookies = request.getCookies();
        String refreshToken = null;
        
        if (cookies != null) {
            log.info("🔧 JWT Filter: Found {} cookies", cookies.length);
            for (Cookie cookie : cookies) {
                log.info("🔧 JWT Filter: Cookie {} = {} (Domain: {}, Path: {})", cookie.getName(), 
                    "accessToken".equals(cookie.getName()) ? cookie.getValue().substring(0, Math.min(20, cookie.getValue().length())) + "..." : "***",
                    cookie.getDomain(), cookie.getPath());
                if ("accessToken".equals(cookie.getName())) {
                    token = cookie.getValue();
                    log.info("🔧 JWT Filter: Found accessToken cookie, length: {}", token != null ? token.length() : 0);
                    break;
                } else if ("refreshToken".equals(cookie.getName())) {
                    refreshToken = cookie.getValue();
                    log.info("🔧 JWT Filter: Found refreshToken cookie, length: {}", refreshToken != null ? refreshToken.length() : 0);
                }
            }
        } else {
            log.info("🔧 JWT Filter: No cookies found");
        }
        
        // Fallback to Authorization header if no cookie found
        if (token == null) {
            String authHeader = request.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String headerToken = authHeader.substring(7);
                // Only use Authorization header if it's not "undefined" or empty
                if (headerToken != null && !headerToken.equals("undefined") && !headerToken.trim().isEmpty()) {
                    token = headerToken;
                    log.info("🔧 JWT Filter: Found valid Authorization header, token length: {}", token.length());
                } else {
                    log.info("🔧 JWT Filter: Found invalid Authorization header (undefined/empty), ignoring");
                }
            } else {
                log.info("🔧 JWT Filter: No Authorization header found");
            }
        }
        
        // Debug: Log all request headers for troubleshooting
        log.info("🔧 JWT Filter: Request headers:");
        java.util.Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            String headerValue = request.getHeader(headerName);
            log.info("🔧 JWT Filter: {} = {}", headerName, headerValue);
        }

        // If no accessToken found but refreshToken exists, try to refresh
        if (token == null && refreshToken != null) {
            log.info("🔧 JWT Filter: No accessToken found, but refreshToken exists. Attempting to refresh...");
            log.info("🔧 JWT Filter: refreshToken length: {}", refreshToken.length());
            try {
                // Validate refresh token and extract member info
                Long memberId = jwtUtil.extractMemberIdFromToken(refreshToken);
                List<GrantedAuthority> roles = jwtUtil.extractRoles(refreshToken);
                
                // Generate new access token
                String newAccessToken = jwtUtil.generateToken(memberId, roles);
                log.info("🔧 JWT Filter: Generated new accessToken, length: {}", newAccessToken.length());
                
                // Set new accessToken cookie
                Cookie newAccessCookie = new Cookie("accessToken", newAccessToken);
                newAccessCookie.setHttpOnly(true);
                newAccessCookie.setPath("/");
                newAccessCookie.setMaxAge(3600); // 1 hour
                response.addCookie(newAccessCookie);
                
                log.info("🔧 JWT Filter: Set new accessToken cookie");
                token = newAccessToken;
                
            } catch (Exception e) {
                log.warn("❌ Failed to refresh access token: {}", e.getMessage());
            }
        }
        
        if (token == null) {
            log.warn("❌ No Authorization header or accessToken cookie found");
            filterChain.doFilter(request, response);
            return;
        }

        try {
        	Long memberId = jwtUtil.extractMemberIdFromToken(token);  // validate and extract claims
            List<GrantedAuthority> roles = jwtUtil.extractRoles(token);

            UsernamePasswordAuthenticationToken authToken =
            	    new UsernamePasswordAuthenticationToken(memberId, null, roles);

            	SecurityContextHolder.getContext().setAuthentication(authToken);
            log.info("✅ JWT authenticated. MemberId: {}, Roles: {}", memberId, roles);

        } catch (Exception e) {
            log.warn("❌ Token validation failed: {}", e.getMessage());
        }
        filterChain.doFilter(request, response);
    }
}
