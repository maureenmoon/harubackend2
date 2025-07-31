package com.study.spring.domain.board.controller;

import com.study.spring.domain.board.dto.BoardDto;
import com.study.spring.domain.board.service.BoardService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/boards")
@RequiredArgsConstructor
public class BoardController {
    private final BoardService boardService;

    // 게시글 생성
    @PostMapping
    public ResponseEntity<BoardDto.Response> createBoard(
            @RequestParam("memberId") Long memberId,  // 수정!
            @RequestBody BoardDto.Request request) {
        return ResponseEntity.ok(boardService.createBoard(memberId, request));
    }

    // 게시글 조회
    @GetMapping("/{id}")
    public ResponseEntity<BoardDto.Response> getBoard(@PathVariable("id") Long id) {
        return ResponseEntity.ok(boardService.getBoard(id));
    }

    // 전체 게시글 조회
    @GetMapping
    public ResponseEntity<List<BoardDto.Response>> getAllBoards() {
        return ResponseEntity.ok(boardService.getAllBoards());
    }

    // 회원별 게시글 조회
    @GetMapping("/member/{memberId}")
    public ResponseEntity<List<BoardDto.Response>> getBoardsByMemberId(
            @PathVariable("memberId") Long memberId) {  // 수정!
        return ResponseEntity.ok(boardService.getBoardsByMemberId(memberId));
    }

    // 게시글 수정
    @PutMapping("/{id}")
    public ResponseEntity<BoardDto.Response> updateBoard(
            @PathVariable("id") Long id,
            @RequestBody BoardDto.Request request) {
        return ResponseEntity.ok(boardService.updateBoard(id, request));
    }

    // 게시글 삭제
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteBoard(@PathVariable("id") Long id) {
        boardService.deleteBoard(id);
        return ResponseEntity.noContent().build();
    }

    // 댓글 추가
    @PostMapping("/{boardId}/comments")
    public ResponseEntity<BoardDto.CommentResponse> addComment(
            @PathVariable("boardId") Long boardId,  // 수정!
            @RequestParam("memberId") Long memberId,  // 수정!
            @RequestBody BoardDto.CommentRequest request) {
        return ResponseEntity.ok(boardService.addComment(boardId, memberId, request));
    }

    // 특정 게시글의 댓글 목록 조회
    @GetMapping("/{boardId}/comments")
    public ResponseEntity<List<BoardDto.CommentResponse>> getCommentsByBoardId(
            @PathVariable("boardId") Long boardId) {  // 수정!
        return ResponseEntity.ok(boardService.getCommentsByBoardId(boardId));
    }

    // 특정 댓글 조회
    @GetMapping("/comments/{commentId}")
    public ResponseEntity<BoardDto.CommentResponse> getComment(
            @PathVariable("commentId") Long commentId) {  // 수정!
        return ResponseEntity.ok(boardService.getComment(commentId));
    }

    // 특정 회원이 작성한 댓글 목록 조회
    @GetMapping("/comments/member/{memberId}")
    public ResponseEntity<List<BoardDto.CommentResponse>> getCommentsByMemberId(
            @PathVariable("memberId") Long memberId) {  // 수정!
        return ResponseEntity.ok(boardService.getCommentsByMemberId(memberId));
    }

    // 댓글 수정
    @PutMapping("/comments/{commentId}")
    public ResponseEntity<BoardDto.CommentResponse> updateComment(
            @PathVariable("commentId") Long commentId,  // 수정!
            @RequestBody BoardDto.CommentRequest request) {
        return ResponseEntity.ok(boardService.updateComment(commentId, request));
    }

    // 댓글 삭제
    @DeleteMapping("/comments/{commentId}")
    public ResponseEntity<Void> deleteComment(@PathVariable("commentId") Long commentId) {  // 수정!
        boardService.deleteComment(commentId);
        return ResponseEntity.noContent().build();
    }
} 