package com.study.spring.domain.member.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.util.UUID;

@Component
public class FileUploadUtil {

    @Value("${file.upload-dir}")
    private String uploadDir;

    public String saveFile(MultipartFile multipartFile) {
        if (multipartFile == null || multipartFile.isEmpty()) {
            return null;
        }

        try {
            // 1. Ensure upload directory exists
            File uploadPath = new File(uploadDir);
            if (!uploadPath.exists()) {
                uploadPath.mkdirs();
            }

            // 2. Generate unique filename
            String originalFilename = multipartFile.getOriginalFilename();
            String extension = originalFilename.substring(originalFilename.lastIndexOf("."));
            String storedFilename = UUID.randomUUID().toString() + extension;

            // 3. Save file to disk
            File saveFile = new File(uploadDir, storedFilename);
            multipartFile.transferTo(saveFile);

            // 4. Return file path (or just name if you're serving it statically)
            return storedFilename;

        } catch (IOException e) {
            throw new RuntimeException("이미지 저장 실패", e);
        }
    }
}