package com.study.spring.domain.security.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class CookieUtil {
	
	//Cookie domain configuration
    @Value("${app.cookie.domain:localhost}")
    private String cookieDomain;

    //Cookie security setting
    @Value("${app.cookie.secure:false}")
    private boolean cookieSecure;

    public void setHttpOnlyCookie(HttpServletResponse response, String name, String value, int maxAge) {
        System.out.println("🔧 COOKIE: Setting cookie: " + name + " = " + (value != null ? value.substring(0, Math.min(20, value.length())) + "..." : "NULL"));
        System.out.println("�� COOKIE: Max age: " + maxAge + " seconds");
        System.out.println("🔧 COOKIE: Domain: " + cookieDomain);
        System.out.println("🔧 COOKIE: Secure: " + cookieSecure);
        
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(cookieSecure);
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        
        if (cookieDomain != null && !cookieDomain.isEmpty() && !"localhost".equals(cookieDomain)) {
            cookie.setDomain(cookieDomain);
        }
        
        String sameSite = "Lax";
        String domainAttribute = (cookieDomain != null && !cookieDomain.isEmpty() && !"localhost".equals(cookieDomain)) ? "; Domain=" + cookieDomain : "";
        String cookieString = String.format("%s=%s; HttpOnly; Path=/; Max-Age=%d; SameSite=%s%s%s", 
            name, value, maxAge, sameSite,
            cookieSecure ? "; Secure" : "",
            domainAttribute
        );
        
        System.out.println("🔧 COOKIE: Setting header: " + cookieString);
        // ✅ FIXED: Use addHeader instead of setHeader
        response.addHeader("Set-Cookie", cookieString);
        
        // Also add the cookie using the traditional method as backup
        response.addCookie(cookie);
        
        System.out.println("✅ COOKIE: Cookie set successfully: " + name);
    }

    public void clearCookie(HttpServletResponse response, String name) {
        System.out.println("🔧 COOKIE: Clearing cookie: " + name);
        
        // Clear with multiple approaches to ensure it works
        Cookie cookie = new Cookie(name, null);
        cookie.setHttpOnly(true);
        cookie.setSecure(cookieSecure);
//        cookie.setPath("/api/members");
        cookie.setMaxAge(0);
        
        // Don't set domain for localhost cookies
        if (cookieDomain != null && !cookieDomain.isEmpty() && !"localhost".equals(cookieDomain)) {
            cookie.setDomain(cookieDomain);
        }
        
        // Set SameSite attribute for CSRF protection
        String sameSite = "Lax"; // Use Lax for cross-site cookies
        String domainAttribute = (cookieDomain != null && !cookieDomain.isEmpty() && !"localhost".equals(cookieDomain)) ? "; Domain=" + cookieDomain : "";
        String cookieString = String.format("%s=; HttpOnly; Path=/; Max-Age=0; SameSite=%s%s%s", 
            name, sameSite,
            cookieSecure ? "; Secure" : "",
            domainAttribute
        );
        
        System.out.println("🔧 COOKIE: Setting clear header: " + cookieString);
        response.setHeader("Set-Cookie", cookieString);
        
        // Also add the cookie using the traditional method as backup
        response.addCookie(cookie);
        
        // Also try clearing with different paths to ensure complete removal
        Cookie cookieRoot = new Cookie(name, null);
        cookieRoot.setPath("/");
        cookieRoot.setMaxAge(0);
        response.addCookie(cookieRoot);
        
        // Try clearing with empty path as well
        Cookie cookieEmptyPath = new Cookie(name, null);
        cookieEmptyPath.setPath("");
        cookieEmptyPath.setMaxAge(0);
        response.addCookie(cookieEmptyPath);
        
        System.out.println("✅ COOKIE: Cookie cleared successfully: " + name);
    }
    
    /**
     * Read cookie value by name from request
     * @param request HttpServletRequest
     * @param name Cookie name
     * @return Cookie value or null if not found
     */
    public String readCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (name.equals(cookie.getName())) {
                    System.out.println("🔧 COOKIE: Read cookie " + name + " = " + cookie.getValue());
                    return cookie.getValue();
                }
            }
        }
        System.out.println("🔧 COOKIE: Cookie " + name + " not found");
        return null;
    }
    
    /**
     * Read recommended calories from cookies
     * @param request HttpServletRequest
     * @return Recommended calories as Integer or null if not found
     */
    public Integer readRecommendedCalories(HttpServletRequest request) {
        String caloriesStr = readCookie(request, "recommendedCalories");
        if (caloriesStr != null) {
            try {
                int calories = Integer.parseInt(caloriesStr);
                System.out.println("🔧 COOKIE: Recommended calories from cookie: " + calories);
                return calories;
            } catch (NumberFormatException e) {
                System.out.println("❌ COOKIE: Invalid recommended calories format: " + caloriesStr);
                return null;
            }
        }
        return null;
    }

    /**
     * Set userData cookie with profile image URL
     * @param response HttpServletResponse
     * @param userDataJson JSON string containing user data including profile image
     */
    public void setUserDataCookie(HttpServletResponse response, String userDataJson) {
        System.out.println("🔧 COOKIE: Setting userData cookie with profile image");
        setHttpOnlyCookie(response, "userData", userDataJson, 7 * 24 * 60 * 60); // 7 days
    }

    /**
     * Read userData cookie
     * @param request HttpServletRequest
     * @return userData JSON string or null if not found
     */
    public String readUserDataCookie(HttpServletRequest request) {
        return readCookie(request, "userData");
    }

    /**
     * Update profile image in userData cookie
     * @param request HttpServletRequest
     * @param response HttpServletResponse
     * @param newProfileImageUrl New profile image URL
     */
    public void updateProfileImageInCookie(HttpServletRequest request, HttpServletResponse response, String newProfileImageUrl) {
        String currentUserData = readUserDataCookie(request);
        if (currentUserData != null) {
            try {
                // Parse current userData and update profileImageUrl
                // This is a simple approach - in production you might want to use a proper JSON library
                String updatedUserData = currentUserData.replaceAll(
                    "\"profileImageUrl\":\"[^\"]*\"", 
                    "\"profileImageUrl\":\"" + newProfileImageUrl + "\""
                );
                setUserDataCookie(response, updatedUserData);
                System.out.println("✅ COOKIE: Profile image updated in userData cookie");
            } catch (Exception e) {
                System.out.println("❌ COOKIE: Failed to update profile image in userData cookie: " + e.getMessage());
            }
        }
    }
} 