package com.study.spring.domain.meal.dto;

import com.study.spring.domain.meal.entity.Food;
import com.study.spring.domain.meal.entity.Meal;
import com.study.spring.domain.meal.entity.MealType;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class MealDto {

    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Builder
    public static class Request {
        private MealType mealType;
        private String imageUrl;
        private String memo;
        private List<FoodRequest> foods;
        private LocalDateTime modifiedAt;
        private Integer totalCalories;
    }

    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Builder
    public static class Response {
        private Long id;
        private Long memberId;
        private MealType mealType;
        private String imageUrl;
        private String memo;
        private List<FoodResponse> foods;
        private LocalDate createdAt;
        private LocalDate updatedAt;
        private LocalDateTime modifiedAt;

        public static Response from(Meal meal) {
            return Response.builder()
                    .id(meal.getId())
                    .memberId(meal.getMember().getId())
                    .mealType(meal.getMealType())
                    .imageUrl(meal.getImageUrl())
                    .memo(meal.getMemo())
                    .foods(meal.getFoods() != null ? 
                            meal.getFoods().stream()
                                    .map(FoodResponse::from)
                                    .collect(Collectors.toList()) : 
                            new ArrayList<>())  // null-safe 처리
                    .createdAt(meal.getCreatedAt() != null ? meal.getCreatedAt().toLocalDate() : null)
                    .updatedAt(meal.getUpdatedAt() != null ? meal.getUpdatedAt().toLocalDate() : null)
                    .modifiedAt(meal.getModifiedAt())
                    .build();
        }
    }

    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Builder
    public static class FoodRequest {
        private String foodName;
        private Integer calories;
        private Float carbohydrate;
        private Float protein;
        private Float fat;
        private Float sodium;
        private Float fiber;
    }

    @NoArgsConstructor
    @AllArgsConstructor
    @Getter
    @Builder
    public static class FoodResponse {
        private Long id;
        private String foodName;
        private Integer calories;
        private Float carbohydrate;
        private Float protein;
        private Float fat;
        private Float sodium;
        private Float fiber;

        public static FoodResponse from(Food food) {
            return FoodResponse.builder()
                    .id(food.getId())
                    .foodName(food.getFoodName())
                    .calories(food.getCalories())
                    .carbohydrate(food.getCarbohydrate())
                    .protein(food.getProtein())
                    .fat(food.getFat())
                    .sodium(food.getSodium())
                    .fiber(food.getFiber())
                    .build();
        }
    }
} 