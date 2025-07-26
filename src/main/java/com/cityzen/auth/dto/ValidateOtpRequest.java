package com.cityzen.auth.dto;
import jakarta.validation.constraints.NotBlank;
public class ValidateOtpRequest {
    @NotBlank
    private String otp;
    public String getOtp() {
        return otp;
    }
    public void setOtp(String otp) {
        this.otp = otp;
    }
}