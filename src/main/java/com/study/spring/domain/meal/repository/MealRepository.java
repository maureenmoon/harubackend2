package com.study.spring.domain.meal.repository;

import com.study.spring.domain.meal.entity.Meal;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;
import java.time.LocalDateTime;

public interface MealRepository extends JpaRepository<Meal, Long> {
    List<Meal> findByMemberIdOrderByModifiedAtDesc(Long memberId);
    List<Meal> findByUpdatedAtBetween(LocalDateTime start, LocalDateTime end);
    List<Meal> findAllByOrderByModifiedAtDesc();
    
    @Query("SELECT m FROM Meal m ORDER BY m.modifiedAt DESC, m.id DESC")
    List<Meal> findAllOrderByModifiedAtDesc();
    
    @Query("SELECT m FROM Meal m WHERE m.member.id = :memberId ORDER BY CASE WHEN m.modifiedAt IS NULL THEN 0 ELSE 1 END DESC, m.modifiedAt DESC, m.id DESC")
    List<Meal> findByMemberIdOrderByModifiedAtDescQuery(@Param("memberId") Long memberId);

    @Query("SELECT m FROM Meal m WHERE m.modifiedAt >= :start AND m.modifiedAt < :end ORDER BY m.modifiedAt DESC, m.id DESC")
    List<Meal> findByModifiedAtBetween(@Param("start") LocalDateTime start, @Param("end") LocalDateTime end);

    @Query("SELECT m FROM Meal m WHERE m.member.id = :memberId AND m.modifiedAt >= :start AND m.modifiedAt < :end ORDER BY m.modifiedAt DESC, m.id DESC")
    List<Meal> findByMemberIdAndModifiedAtBetween(@Param("memberId") Long memberId, @Param("start") LocalDateTime start, @Param("end") LocalDateTime end);
} 