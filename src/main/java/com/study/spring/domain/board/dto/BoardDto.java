package com.study.spring.domain.board.dto;

import com.study.spring.domain.board.entity.Board;
import com.study.spring.domain.board.entity.Comment;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;


public class BoardDto {

   
    @AllArgsConstructor
    @NoArgsConstructor
    @Getter
    @Builder
    public static class Request {
        private String title;
        private String content;
    }

    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Builder
    public static class Response {
        private Long id;
        private Long memberId;
        private String title;
        private String content;
        private List<CommentResponse> comments;
        private LocalDateTime createdAt;
        private LocalDateTime updatedAt;

        public static Response from(Board board) {
            return Response.builder()
                    .id(board.getId())
                    .memberId(board.getMember().getId())
                    .title(board.getTitle())
                    .content(board.getContent())
                    .comments(board.getComments() != null ? 
                            board.getComments().stream()
                                    .map(CommentResponse::from)
                                    .collect(Collectors.toList()) : 
                            new ArrayList<>())  // null-safe 처리
                    .createdAt(board.getCreatedAt())
                    .updatedAt(board.getUpdatedAt())
                    .build();
        }
    }

    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Builder
    public static class CommentRequest {
        private String content;
    }

    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Builder
    public static class CommentResponse {
        private Long id;
        private Long memberId;
        private String content;
        private LocalDateTime createdAt;

        public static CommentResponse from(Comment comment) {
            return CommentResponse.builder()
                    .id(comment.getId())
                    .memberId(comment.getMember().getId())
                    .content(comment.getContent())
                    .createdAt(comment.getCreatedAt())
                    .build();
        }
    }
} 