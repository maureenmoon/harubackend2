package com.study.spring.domain.security.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import com.study.spring.domain.security.exception.CustomJWTException;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.HashMap;
import java.util.UUID;


@Component
public class JWTUtil {

	private static final Logger log = LoggerFactory.getLogger(JWTUtil.class);
			
	private static final String SECRET = "123456789123456789123456789123456789"; // Should be 256-bit key
    private SecretKey key;

    @PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
    }

    public String generateToken(Map<String, Object> claims, int minutes) {
        // Create a copy of claims to avoid modifying the original
        Map<String, Object> accessClaims = new HashMap<>(claims);
        // Add a unique identifier for access tokens
        accessClaims.put("tokenType", "access");
        accessClaims.put("jti", UUID.randomUUID().toString()); // Unique JWT ID
        return Jwts.builder()
                .setHeader(Map.of("typ", "JWT"))
                .setClaims(accessClaims)
                .setIssuedAt(Date.from(ZonedDateTime.now().toInstant()))
                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(minutes).toInstant()))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public Claims getClaims(String token) throws JwtException {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public Map<String, Object> validateToken(String token) {
        try {        	
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (MalformedJwtException e) {
            throw new CustomJWTException("MalFormed");
        } catch (ExpiredJwtException e) {
            throw new CustomJWTException("Expired");
        } catch (InvalidClaimException e) {
            throw new CustomJWTException("Invalid");
        } catch (JwtException e) {
            throw new CustomJWTException("JWTError");
        } catch (Exception e) {
            throw new CustomJWTException("Error");
        }
    }
    
    //refresh token issued separately from access tokens
    public String generateRefreshToken(Map<String, Object> claims, int days) {
        // Create a copy of claims to avoid modifying the original
        Map<String, Object> refreshClaims = new HashMap<>(claims);
        // Add a unique identifier for refresh tokens
        refreshClaims.put("tokenType", "refresh");
        refreshClaims.put("jti", UUID.randomUUID().toString()); // Unique JWT ID
        // Add a small delay to ensure different timestamp
        return Jwts.builder()
                .setHeader(Map.of("typ", "JWT"))
                .setClaims(refreshClaims)
                .setIssuedAt(Date.from(ZonedDateTime.now().plusNanos(1).toInstant()))
                .setExpiration(Date.from(ZonedDateTime.now().plusDays(days).toInstant()))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }
    
    //img to supabase
    public String extractTokenFromRequest(HttpServletRequest request) {
        String bearer = request.getHeader("Authorization");
        return (bearer != null && bearer.startsWith("Bearer ")) 
            ? bearer.substring(7) : null;
    }

//    public String extractEmailFromToken(String token) {
//        if (token == null) return null;
//        Claims claims = getClaims(token);
//        return (String) claims.get("email");
//    }
    
//    public String validateAndExtractEmail(String token) {
//        try {
//            Claims claims = getClaims(token);
//            return (String) claims.get("email"); // ✅ your token uses "email"
//        } catch (Exception e) {
//            log.warn("❌ Failed to extract email from token: {}", e.getMessage());
//            throw new CustomJWTException("Invalid token: " + e.getMessage());
//        }
//    }
    
    public Long extractMemberIdFromToken(String token) {
        if (token == null) return null;
        Claims claims = getClaims(token);
        return claims.get("memberId", Long.class); // ✅ clearly scoped
    }
    
    public List<GrantedAuthority> extractRoles(String token) {
        try {
            Claims claims = getClaims(token);
            List<String> roleList = claims.get("roles", List.class);

            if (roleList == null) {
                throw new CustomJWTException("Token contains no roles");
            }

            return roleList.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

        } catch (Exception e) {
        	log.warn("❌ Failed to extract roles from token: {}", e.getMessage());
            throw new CustomJWTException("Invalid roles");
        }
    }
    
    // Generate access token with memberId and roles
    public String generateToken(Long memberId, List<GrantedAuthority> roles) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("memberId", memberId);
        claims.put("roles", roles.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));
        claims.put("tokenType", "access");
        claims.put("jti", UUID.randomUUID().toString());
        
        return Jwts.builder()
                .setHeader(Map.of("typ", "JWT"))
                .setClaims(claims)
                .setIssuedAt(Date.from(ZonedDateTime.now().toInstant()))
                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(60).toInstant()))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }
} 
