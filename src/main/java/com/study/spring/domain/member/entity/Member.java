package com.study.spring.domain.member.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Builder(toBuilder = true)
@AllArgsConstructor
@Entity
@Table(name = "member")
@Getter
@NoArgsConstructor
public class Member {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(unique = true, nullable = false)
	private String email;

	@Column(nullable = false)
	private String password;

	@Column(nullable = false)
	private String nickname;

	@Column(nullable = false)
	private String name;

	@Column(nullable = false)
	private LocalDate birthAt;

	@Enumerated(EnumType.STRING)
	private Gender gender;

	@Column(nullable = false)
	private Float height;

	@Column(nullable = false)
	private Float weight;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false)
	private ActivityLevel activityLevel;

	// img to supabase
	@Setter
	private String profileImageUrl;

	@Enumerated(EnumType.STRING)
	@Builder.Default
	private Role role = Role.USER;

	private LocalDateTime createdAt;
	private LocalDateTime updatedAt;

	@PrePersist
	protected void onCreate() {
		createdAt = LocalDateTime.now();
		updatedAt = LocalDateTime.now();
	}

	@PreUpdate
	protected void onUpdate() {
		updatedAt = LocalDateTime.now();
	}

	// 정적 팩토리 메서드
	public static MemberBuilder createMember() {
		return Member.builder().role(Role.USER).createdAt(LocalDateTime.now()).updatedAt(LocalDateTime.now());
	}

	// JWT with refresh tokens
	@Column(name = "refresh_token", length = 1000)
	private String refreshToken;

	public void updateRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	public void setPassword(String encode) {
		this.password = encode;
	}
	
	/**
	 * Calculate recommended daily calories using Mifflin-St Jeor equation
	 * BMR = 10 × weight(kg) + 6.25 × height(cm) - 5 × age(years) + 5 (male) or -161 (female)
	 * TDEE = BMR × Activity Multiplier
	 * 
	 * This matches the frontend calculation exactly
	 */
	public int calculateRecommendedCalories() {
		// Calculate age from birthAt (matching frontend logic)
		int age = java.time.LocalDate.now().getYear() - birthAt.getYear();
		if (birthAt.plusYears(age).isAfter(java.time.LocalDate.now())) {
			age--; // Adjust if birthday hasn't occurred this year
		}
		
		// Parse height and weight (matching frontend parseFloat logic)
		double h = height.doubleValue();
		double w = weight.doubleValue();
		
		// Mifflin-St Jeor BMR calculation (matching frontend exactly)
		double bmr;
		if (gender == Gender.MALE) {
			bmr = 10 * w + 6.25 * h - 5 * age + 5;
		} else {
			bmr = 10 * w + 6.25 * h - 5 * age - 161;
		}
		
		// Activity level multipliers (matching frontend exactly)
		double activityFactor = 1.55; // Default (MODERATE)
		if (activityLevel == ActivityLevel.LOW) {
			activityFactor = 1.375; // 조금 활동적
		} else if (activityLevel == ActivityLevel.HIGH) {
			activityFactor = 1.725; // 매우 활동적
		}
		// MODERATE stays at 1.55
		
		// Calculate Total Daily Energy Expenditure (TDEE) - matching frontend Math.round
		int tdee = (int) Math.round(bmr * activityFactor);
		
		System.out.println("🔧 CALORIES: Age: " + age + ", BMR: " + Math.round(bmr) + 
			", Activity: " + activityLevel + " (x" + activityFactor + "), TDEE: " + tdee);
		
		return tdee;
	}
}