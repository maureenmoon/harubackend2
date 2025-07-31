package com.study.spring.domain.email;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {
    
//    @Qualifier("naverSender") // Use Naver for ALL emails
    @Autowired
    private JavaMailSender mailSender;
    
    public void sendPasswordResetEmail(String to, String name, String temporaryPassword) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("susiemoon@naver.com"); // Replace with your actual Naver email
        message.setTo(to); // Can send to ANY email address
        message.setSubject("[하루칼로리] 비밀번호 재설정");
        message.setText(
            "안녕하세요, " + name + "님!\n\n" +
            "비밀번호 재설정 요청이 접수되었습니다.\n\n" +
            "임시 비밀번호: " + temporaryPassword + "\n\n" +
            "보안을 위해 로그인 후 반드시 비밀번호를 변경해주세요.\n\n" +
            "감사합니다.\n" +
            "하루칼로리 팀"
        );
        
        try {
            mailSender.send(message);
            System.out.println("✅ Email sent successfully to: " + to);
        } catch (Exception e) {
            System.out.println("❌ Failed to send email: " + e.getMessage());
            throw e;
        }
    }
}