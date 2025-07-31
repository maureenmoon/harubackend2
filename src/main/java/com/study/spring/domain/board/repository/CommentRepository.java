package com.study.spring.domain.board.repository;

import com.study.spring.domain.board.entity.Comment;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface CommentRepository extends JpaRepository<Comment, Long> {
    List<Comment> findByBoardId(Long boardId);
    List<Comment> findByMemberId(Long memberId);
} 