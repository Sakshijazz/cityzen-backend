package com.cityzen.auth.dto;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
public class ForgotPasswordRequest {
    @Email
    @NotBlank
    private String email;
    // Getters and Setters
}