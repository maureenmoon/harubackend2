//package com.study.spring.domain.member.service;
//
//import com.study.spring.domain.member.entity.Member;
//import com.study.spring.domain.member.repository.MemberRepository;
//import lombok.RequiredArgsConstructor;
//import org.springframework.boot.CommandLineRunner;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Component;
//
//@Component
//@RequiredArgsConstructor
//public class PasswordEncryptor implements CommandLineRunner {
//
//    private final MemberRepository memberRepository;
//    private final PasswordEncoder passwordEncoder;
//
//    @Override
//    public void run(String... args) {
//        System.out.println("🔐 PasswordEncryptor starting...");
//
//        memberRepository.findAll().forEach(member -> {
//            String rawPassword = member.getPassword();
//
//            if (!rawPassword.startsWith("$2a$")) {
//                member.setPassword(passwordEncoder.encode(rawPassword));
//                memberRepository.save(member);
//                System.out.println("✅ Password encoded for: " + member.getNickname());
//            } else {
//                System.out.println("🔁 Already encoded: " + member.getNickname());
//            }
//        });
//
//        System.out.println("🔐 PasswordEncryptor completed.");
//    }
//}
