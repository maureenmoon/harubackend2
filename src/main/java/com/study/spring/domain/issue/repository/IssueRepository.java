package com.study.spring.domain.issue.repository;

import com.study.spring.domain.issue.entity.Issue;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface IssueRepository extends JpaRepository<Issue, Long> {
    List<Issue> findByAdminId(Long adminId);
} 