package com.study.spring.domain.meal.controller;

import com.study.spring.domain.meal.dto.MealDto;
import com.study.spring.domain.meal.entity.Meal;
import com.study.spring.domain.meal.entity.MealType;
import com.study.spring.domain.meal.service.MealService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDate;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/meals")
@CrossOrigin(origins = "http://localhost:5173")
@RequiredArgsConstructor
public class MealController {
    private final MealService mealService;

    // 식사 기록 생성
    @PostMapping
    public ResponseEntity<MealDto.Response> createMeal(
            @RequestParam("memberId") Long memberId,  // 이름 명시
            @RequestBody MealDto.Request request) {
        return ResponseEntity.ok(mealService.createMeal(memberId, request));
    }

    // 특정 식사 기록 조회
    @GetMapping("/{id}")
    public ResponseEntity<MealDto.Response> getMeal(@PathVariable("id") Long id) {
        return ResponseEntity.ok(mealService.getMeal(id));
    }

    // 전체 식사 기록 조회
    @GetMapping
    public ResponseEntity<List<MealDto.Response>> getAllMeals() {
        return ResponseEntity.ok(mealService.getAllMeals());
    }

    // 회원별 식사 기록 조회
    @GetMapping("/member/{memberId}")
    public ResponseEntity<List<MealDto.Response>> getMealsByMemberId(
            @PathVariable("memberId") Long memberId) {  // 이름 명시
        return ResponseEntity.ok(mealService.getMealsByMemberId(memberId));
    }

    // 회원별 + 식사타입별 조회
    @GetMapping("/member/{memberId}/type/{mealType}")
    public ResponseEntity<List<MealDto.Response>> getMealsByMemberIdAndMealType(
            @PathVariable("memberId") Long memberId,
            @PathVariable("mealType") MealType mealType) {
        return ResponseEntity.ok(mealService.getMealsByMemberIdAndMealType(memberId, mealType));
    }

    // updatedAt 날짜로 식사 기록 조회
    @GetMapping("/modified-date")
    public ResponseEntity<List<MealDto.Response>> getMealsByModifiedDate(@RequestParam("date") String dateStr) {
        LocalDate date = LocalDate.parse(dateStr);
        return ResponseEntity.ok(mealService.getMealsByModifiedDate(date));
    }

    // 회원별 + modifiedAt 날짜로 식사 기록 조회
    @GetMapping("/modified-date/member/{memberId}")
    public ResponseEntity<?> getMealsByMemberIdAndModifiedDate(@PathVariable("memberId") Long memberId, @RequestParam("date") String dateStr) {
        LocalDate date = LocalDate.parse(dateStr);
        List<MealDto.Response> result = mealService.getMealsByMemberIdAndModifiedDate(memberId, date);
        if (result.isEmpty()) {
            return ResponseEntity.ok(Collections.singletonMap("message", "nodata"));
        }
        return ResponseEntity.ok(result);
    }

    // modifiedAt(문자열)로 식사 기록 조회
    // @GetMapping("/modified-date")
    // public ResponseEntity<List<MealDto.Response>> getMealsByModifiedAt(@RequestParam("modifiedAt") String modifiedAt) {
    //     // MealService에 getMealsByModifiedAt(String) 메서드가 없다는 오류가 발생하므로, 
    //     // 올바른 메서드명을 사용하거나 MealService에 해당 메서드가 구현되어 있는지 확인해야 합니다.
    //     // 예시로, getMealsByModifiedAt이 아니라 getMealsByModifiedDate(String)일 수 있으니 아래와 같이 수정합니다.
    //     return ResponseEntity.ok(mealService.getMealsByModifiedAt(modifiedAt));
    // }

    // 식사 기록 수정
    @PutMapping("/{id}")
    public ResponseEntity<MealDto.Response> updateMeal(
            @PathVariable("id") Long id,
            @RequestBody MealDto.Request request) {
        return ResponseEntity.ok(mealService.updateMeal(id, request));
    }

    // 식사 이미지만 수정
    // @PatchMapping("/{id}/image")
    // public ResponseEntity<Void> updateMealImage(
    //         @PathVariable("id") Long id,
    //         @RequestBody Map<String, String> body) {
    //     String imageUrl = body.get("imageUrl");
    //     mealService.updateMealImage(id, imageUrl);
    //     return ResponseEntity.noContent().build();
    // }

    // 식사 이미지 업로드
    // @PatchMapping(value = "/{id}/image-upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    // public ResponseEntity<Void> uploadMealImage(
    //         @PathVariable("id") Long id,
    //         @RequestPart("image") org.springframework.web.multipart.MultipartFile imageFile) {
    //     mealService.uploadMealImage(id, imageFile);
    //     return ResponseEntity.noContent().build();
    // }

    // 식사 기록 삭제
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteMeal(@PathVariable("id") Long id) {
        mealService.deleteMeal(id);
        return ResponseEntity.noContent().build();
    }

    // 식사 이미지 저장
    // @PostMapping("/{id}/")
    // public void testCreate(@ModelAttribute MealDto.Request request) {
    //     mealService.uploadMealImage(request);
    // }
} 