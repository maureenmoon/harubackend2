package com.study.spring.domain.member.util;

import lombok.extern.slf4j.Slf4j;
import net.coobird.thumbnailator.Thumbnails;
import net.coobird.thumbnailator.geometry.Positions;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Component
public class ImageProcessingUtil {

    @Value("${file.upload-dir}")
    private String uploadDir;

    // Configuration constants
    private static final int MAX_WIDTH = 1200;
    private static final int MAX_HEIGHT = 1200;
    private static final int THUMBNAIL_SIZE = 200;
    private static final float QUALITY = 0.8f; // 80% quality for compression

    /**
     * Process image with compression, thumbnail generation, and smart naming
     * @param multipartFile Original image file
     * @return Map containing main image path, thumbnail path, and metadata
     */
    public Map<String, Object> processImage(MultipartFile multipartFile) {
        if (multipartFile == null || multipartFile.isEmpty()) {
            return null;
        }

        try {
            // 1. Ensure upload directory exists
            File uploadPath = new File(uploadDir);
            if (!uploadPath.exists()) {
                uploadPath.mkdirs();
            }

            // 2. Generate smart filename with timestamp
            String originalFilename = multipartFile.getOriginalFilename();
            String extension = getFileExtension(originalFilename);
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyMMddHHmm"));
            String baseFilename = timestamp + "_" + getFilenameWithoutExtension(originalFilename);
            
            String mainImageFilename = baseFilename + extension;
            String thumbnailFilename = baseFilename + "_thumb" + extension;

            // 3. Process original image (compress and resize if needed)
            BufferedImage originalImage = ImageIO.read(multipartFile.getInputStream());
            BufferedImage processedImage = processMainImage(originalImage);
            
            // 4. Create thumbnail
            BufferedImage thumbnailImage = createThumbnail(originalImage);

            // 5. Save both images
            File mainImageFile = new File(uploadDir, mainImageFilename);
            File thumbnailFile = new File(uploadDir, thumbnailFilename);

            // Save main image with compression
            ByteArrayOutputStream mainOutputStream = new ByteArrayOutputStream();
            ImageIO.write(processedImage, getImageFormat(extension), mainOutputStream);
            
            // Compress and save
            byte[] mainImageBytes = compressImage(mainOutputStream.toByteArray(), extension);
            java.nio.file.Files.write(mainImageFile.toPath(), mainImageBytes);

            // Save thumbnail
            ImageIO.write(thumbnailImage, getImageFormat(extension), thumbnailFile);

            // 6. Calculate file sizes and compression ratio
            long originalSize = multipartFile.getSize();
            long processedSize = mainImageFile.length();
            long thumbnailSize = thumbnailFile.length();
            double compressionRatio = ((double) (originalSize - processedSize) / originalSize) * 100;

            // 7. Return results
            Map<String, Object> result = new HashMap<>();
            result.put("mainImagePath", mainImageFilename);
            result.put("thumbnailPath", thumbnailFilename);
            result.put("originalSize", originalSize);
            result.put("processedSize", processedSize);
            result.put("thumbnailSize", thumbnailSize);
            result.put("compressionRatio", compressionRatio);
            result.put("timestamp", timestamp);
            result.put("originalFilename", originalFilename);

            log.info("Image processed successfully: {} -> {} (compression: {:.1f}%)", 
                    originalFilename, mainImageFilename, compressionRatio);

            return result;

        } catch (IOException e) {
            log.error("Image processing failed", e);
            throw new RuntimeException("이미지 처리 실패", e);
        }
    }

    /**
     * Process main image - resize if too large and optimize quality
     */
    private BufferedImage processMainImage(BufferedImage originalImage) throws IOException {
        int originalWidth = originalImage.getWidth();
        int originalHeight = originalImage.getHeight();

        // Check if resizing is needed
        if (originalWidth <= MAX_WIDTH && originalHeight <= MAX_HEIGHT) {
            return originalImage; // No resizing needed
        }

        // Calculate new dimensions maintaining aspect ratio
        double scale = Math.min((double) MAX_WIDTH / originalWidth, (double) MAX_HEIGHT / originalHeight);
        int newWidth = (int) (originalWidth * scale);
        int newHeight = (int) (originalHeight * scale);

        log.info("Resizing image from {}x{} to {}x{}", originalWidth, originalHeight, newWidth, newHeight);

        return Thumbnails.of(originalImage)
                .size(newWidth, newHeight)
                .outputQuality(QUALITY)
                .asBufferedImage();
    }

    /**
     * Create thumbnail image
     */
    private BufferedImage createThumbnail(BufferedImage originalImage) throws IOException {
        return Thumbnails.of(originalImage)
                .size(THUMBNAIL_SIZE, THUMBNAIL_SIZE)
                .crop(Positions.CENTER) // Crop to square if needed
                .outputQuality(0.7f) // Lower quality for thumbnail
                .asBufferedImage();
    }

    /**
     * Compress image bytes
     */
    private byte[] compressImage(byte[] imageBytes, String extension) throws IOException {
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(imageBytes));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        
        ImageIO.write(image, getImageFormat(extension), outputStream);
        return outputStream.toByteArray();
    }

    /**
     * Get file extension from filename
     */
    private String getFileExtension(String filename) {
        if (filename == null || filename.lastIndexOf(".") == -1) {
            return ".jpg"; // Default extension
        }
        return filename.substring(filename.lastIndexOf(".")).toLowerCase();
    }

    /**
     * Get filename without extension
     */
    private String getFilenameWithoutExtension(String filename) {
        if (filename == null || filename.lastIndexOf(".") == -1) {
            return filename;
        }
        return filename.substring(0, filename.lastIndexOf("."));
    }

    /**
     * Get image format from file extension
     */
    private String getImageFormat(String extension) {
        switch (extension.toLowerCase()) {
            case ".png":
                return "PNG";
            case ".gif":
                return "GIF";
            case ".bmp":
                return "BMP";
            case ".jpg":
            case ".jpeg":
            default:
                return "JPEG";
        }
    }

    /**
     * Delete image files (both main and thumbnail)
     */
    public void deleteImageFiles(String mainImagePath, String thumbnailPath) {
        try {
            if (mainImagePath != null) {
                File mainFile = new File(uploadDir, mainImagePath);
                if (mainFile.exists()) {
                    mainFile.delete();
                    log.info("Deleted main image: {}", mainImagePath);
                }
            }
            
            if (thumbnailPath != null) {
                File thumbFile = new File(uploadDir, thumbnailPath);
                if (thumbFile.exists()) {
                    thumbFile.delete();
                    log.info("Deleted thumbnail: {}", thumbnailPath);
                }
            }
        } catch (Exception e) {
            log.error("Error deleting image files", e);
        }
    }
} 