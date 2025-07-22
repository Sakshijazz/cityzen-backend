package com.cityzen.auth.dto;
import jakarta.validation.constraints.NotBlank;
public class ChangePasswordRequest {
    @NotBlank
    private String currentPassword;
    @NotBlank
    private String newPassword;
    // Getters and Setters
}