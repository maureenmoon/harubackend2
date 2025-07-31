package com.study.spring.domain.issue.controller;

import com.study.spring.domain.issue.dto.IssueDto;
import com.study.spring.domain.issue.service.IssueService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/issues")
@RequiredArgsConstructor
public class IssueController {
    private final IssueService issueService;

    @PostMapping
    public ResponseEntity<IssueDto.Response> createIssue(
            @RequestParam Long adminId,
            @RequestBody IssueDto.Request request) {
        return ResponseEntity.ok(issueService.createIssue(adminId, request));
    }

    @GetMapping("/{id}")
    public ResponseEntity<IssueDto.Response> getIssue(@PathVariable Long id) {
        return ResponseEntity.ok(issueService.getIssue(id));
    }

    @GetMapping("/admin/{adminId}")
    public ResponseEntity<List<IssueDto.Response>> getIssuesByAdminId(@PathVariable Long adminId) {
        return ResponseEntity.ok(issueService.getIssuesByAdminId(adminId));
    }

    @PutMapping("/{id}")
    public ResponseEntity<IssueDto.Response> updateIssue(
            @PathVariable Long id,
            @RequestBody IssueDto.Request request) {
        return ResponseEntity.ok(issueService.updateIssue(id, request));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteIssue(@PathVariable Long id) {
        issueService.deleteIssue(id);
        return ResponseEntity.noContent().build();
    }
} 