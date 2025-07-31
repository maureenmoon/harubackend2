package com.study.spring.domain.member.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

@Slf4j
@Component
public class SupabaseStorageUtil {

    @Value("${file.upload-dir}")
    private String uploadDir;

    @Value("${supabase.url:https://admehgvqowpibiuwugpv.supabase.co}")
    private String supabaseUrl;

    @Value("${supabase.bucket:harukcal}")
    private String bucketName;

    /**
     * Generate a Supabase storage URL for a file
     */
    public String generateSupabaseUrl(String fileName) {
        return String.format("%s/storage/v1/object/public/%s/member/%s", 
            supabaseUrl, bucketName, fileName);
    }

    /**
     * Generate a unique filename with timestamp
     */
    public String generateUniqueFileName(String originalFilename) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyMMddHHmm"));
        String extension = getFileExtension(originalFilename);
        String baseName = originalFilename.substring(0, originalFilename.lastIndexOf('.'));
        
        return String.format("%s_%s%s", timestamp, baseName, extension);
    }

    /**
     * Extract file extension
     */
    private String getFileExtension(String filename) {
        if (filename == null || !filename.contains(".")) {
            return "";
        }
        return filename.substring(filename.lastIndexOf('.'));
    }

    /**
     * Save file locally (for Supabase upload)
     */
    public String saveFileLocally(MultipartFile file) throws IOException {
        String fileName = generateUniqueFileName(file.getOriginalFilename());
        Path uploadPath = Paths.get(uploadDir);
        
        if (!Files.exists(uploadPath)) {
            Files.createDirectories(uploadPath);
        }
        
        Path filePath = uploadPath.resolve(fileName);
        Files.copy(file.getInputStream(), filePath);
        
        log.info("File saved locally: {}", filePath);
        return fileName;
    }

    /**
     * Delete local file after Supabase upload
     */
    public void deleteLocalFile(String fileName) {
        try {
            Path filePath = Paths.get(uploadDir, fileName);
            if (Files.exists(filePath)) {
                Files.delete(filePath);
                log.info("Local file deleted: {}", fileName);
            }
        } catch (IOException e) {
            log.warn("Failed to delete local file: {}", fileName, e);
        }
    }

    /**
     * Extract filename from Supabase URL
     */
    public String extractFileNameFromUrl(String supabaseUrl) {
        if (supabaseUrl == null || !supabaseUrl.contains("/")) {
            return null;
        }
        return supabaseUrl.substring(supabaseUrl.lastIndexOf("/") + 1);
    }

    /**
     * Check if URL is a valid Supabase storage URL
     */
    public boolean isValidSupabaseUrl(String url) {
        return url != null && url.startsWith(supabaseUrl) && url.contains("/storage/v1/object/public/");
    }
} 