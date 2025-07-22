package com.cityzen.auth.dto;
import jakarta.validation.constraints.NotBlank;
public class ResetPasswordRequest {
    @NotBlank
    private String token;
    @NotBlank
    private String newPassword;
    // Getters and Setters
}