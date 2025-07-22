package com.cityzen.auth.entity;
import jakarta.persistence.*;
import java.time.LocalDateTime;
@Entity
public class ForgotPasswordToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String email;
    private String token;
    private LocalDateTime expiryDate;
    // Getters and Setters
}