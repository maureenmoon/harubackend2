package com.study.spring.domain.meal.repository;

import com.study.spring.domain.meal.entity.Food;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface FoodRepository extends JpaRepository<Food, Long> {
    List<Food> findByMealId(Long mealId);
    void deleteAllByMealId(Long mealId);
} 