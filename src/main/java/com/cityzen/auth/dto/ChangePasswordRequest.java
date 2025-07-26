package com.cityzen.auth.dto;
import jakarta.validation.constraints.NotBlank;
public class ChangePasswordRequest {
    @NotBlank
    private String currentPassword;
    @NotBlank
    private String newPassword;
    // Getters and Setters
    public String getCurrentPassword() {
        return currentPassword; // Return the actual current password
    }
    public void setCurrentPassword(String currentPassword) {
        this.currentPassword = currentPassword;
    }
    public String getNewPassword() {
        return newPassword; // Return the actual new password
    }
    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }
}