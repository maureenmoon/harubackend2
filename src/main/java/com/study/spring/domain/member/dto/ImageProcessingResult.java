package com.study.spring.domain.member.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ImageProcessingResult {
    
    private String mainImagePath;
    private String thumbnailPath;
    private String mainImageUrl;
    private String thumbnailUrl;
    private long originalSize;
    private long processedSize;
    private long thumbnailSize;
    private double compressionRatio;
    private String timestamp;
    private String originalFilename;
    private String message;
    private boolean success;
    
    // Helper method to create success result
    public static ImageProcessingResult success(String mainImagePath, String thumbnailPath, 
                                               long originalSize, long processedSize, long thumbnailSize,
                                               String timestamp, String originalFilename) {
        return ImageProcessingResult.builder()
                .mainImagePath(mainImagePath)
                .thumbnailPath(thumbnailPath)
                .mainImageUrl("/images/" + mainImagePath)
                .thumbnailUrl("/images/" + thumbnailPath)
                .originalSize(originalSize)
                .processedSize(processedSize)
                .thumbnailSize(thumbnailSize)
                .compressionRatio(((double) (originalSize - processedSize) / originalSize) * 100)
                .timestamp(timestamp)
                .originalFilename(originalFilename)
                .success(true)
                .message("Image processed successfully")
                .build();
    }
    
    // Helper method to create error result
    public static ImageProcessingResult error(String message) {
        return ImageProcessingResult.builder()
                .success(false)
                .message(message)
                .build();
    }
} 