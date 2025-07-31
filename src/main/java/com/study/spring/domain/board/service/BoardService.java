package com.study.spring.domain.board.service;

import com.study.spring.domain.board.dto.BoardDto;
import com.study.spring.domain.board.entity.Board;
import com.study.spring.domain.board.entity.Comment;
import com.study.spring.domain.board.repository.BoardRepository;
import com.study.spring.domain.board.repository.CommentRepository;
import com.study.spring.domain.member.entity.Member;
import com.study.spring.domain.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class BoardService {
    private final BoardRepository boardRepository;
    private final CommentRepository commentRepository;
    private final MemberRepository memberRepository;

    @Transactional
    public BoardDto.Response createBoard(Long memberId, BoardDto.Request request) {
        // 회원 존재 확인
        Member member = memberRepository.findById(memberId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "회원을 찾을 수 없습니다."));

        // 게시글 엔티티 생성
        Board board = Board.builder()
                .member(member)
                .title(request.getTitle())
                .content(request.getContent())
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();

        Board savedBoard = boardRepository.save(board);
        return BoardDto.Response.from(savedBoard);
    }

    public BoardDto.Response getBoard(Long id) {
        Board board = boardRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "게시글을 찾을 수 없습니다."));
        
        return BoardDto.Response.from(board);
    }

    public List<BoardDto.Response> getAllBoards() {
        return boardRepository.findAll().stream()
                .map(BoardDto.Response::from)
                .collect(Collectors.toList());
    }

    public List<BoardDto.Response> getBoardsByMemberId(Long memberId) {
        return boardRepository.findByMemberId(memberId).stream()
                .map(BoardDto.Response::from)
                .collect(Collectors.toList());
    }

    @Transactional
    public BoardDto.Response updateBoard(Long id, BoardDto.Request request) {
        Board board = boardRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "게시글을 찾을 수 없습니다."));

        // 게시글 정보 업데이트
        Board updatedBoard = board.toBuilder()
                .title(request.getTitle())
                .content(request.getContent())
                .updatedAt(LocalDateTime.now())
                .build();

        Board savedBoard = boardRepository.save(updatedBoard);
        return BoardDto.Response.from(savedBoard);
    }

    @Transactional
    public void deleteBoard(Long id) {
        Board board = boardRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "게시글을 찾을 수 없습니다."));

        boardRepository.delete(board);
    }

    @Transactional
    public BoardDto.CommentResponse addComment(Long boardId, Long memberId, BoardDto.CommentRequest request) {
        // 게시글 존재 확인
        Board board = boardRepository.findById(boardId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "게시글을 찾을 수 없습니다."));

        // 회원 존재 확인
        Member member = memberRepository.findById(memberId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "회원을 찾을 수 없습니다."));

        // 댓글 엔티티 생성
        Comment comment = Comment.builder()
                .board(board)
                .member(member)
                .content(request.getContent())
                .createdAt(LocalDateTime.now())
                .build();

        Comment savedComment = commentRepository.save(comment);
        return BoardDto.CommentResponse.from(savedComment);
    }

    public List<BoardDto.CommentResponse> getCommentsByBoardId(Long boardId) {
        // 게시글 존재 확인
        boardRepository.findById(boardId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "게시글을 찾을 수 없습니다."));

        return commentRepository.findByBoardId(boardId).stream()
                .map(BoardDto.CommentResponse::from)
                .collect(Collectors.toList());
    }

    public BoardDto.CommentResponse getComment(Long commentId) {
        Comment comment = commentRepository.findById(commentId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "댓글을 찾을 수 없습니다."));
        
        return BoardDto.CommentResponse.from(comment);
    }

    public List<BoardDto.CommentResponse> getCommentsByMemberId(Long memberId) {
        // 회원 존재 확인
        memberRepository.findById(memberId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "회원을 찾을 수 없습니다."));

        return commentRepository.findByMemberId(memberId).stream()
                .map(BoardDto.CommentResponse::from)
                .collect(Collectors.toList());
    }

    @Transactional
    public BoardDto.CommentResponse updateComment(Long commentId, BoardDto.CommentRequest request) {
        Comment comment = commentRepository.findById(commentId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "댓글을 찾을 수 없습니다."));

        // 댓글 내용 수정
        Comment updatedComment = comment.toBuilder()
                .content(request.getContent())
                .build();

        Comment savedComment = commentRepository.save(updatedComment);
        return BoardDto.CommentResponse.from(savedComment);
    }

    @Transactional
    public void deleteComment(Long commentId) {
        Comment comment = commentRepository.findById(commentId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "댓글을 찾을 수 없습니다."));

        commentRepository.delete(comment);
    }
} 