package com.study.spring.domain.board.repository;

import com.study.spring.domain.board.entity.Board;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface BoardRepository extends JpaRepository<Board, Long> {
    List<Board> findByMemberId(Long memberId);
} 