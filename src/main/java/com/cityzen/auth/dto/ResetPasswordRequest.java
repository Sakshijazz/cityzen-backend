package com.cityzen.auth.dto;
import jakarta.validation.constraints.NotBlank;
public class ResetPasswordRequest {
    @NotBlank
    private String token;
    @NotBlank
    private String newPassword;
    public String getToken() {
        return token; // Return the actual token
    }
    public void setToken(String token) {
        this.token = token;
    }
    public String getNewPassword() {
        return newPassword; // Return the actual new password
    }
    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }
}