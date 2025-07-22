package com.cityzen.auth.service;
import org.springframework.stereotype.Service;
import java.util.concurrent.ConcurrentHashMap;
@Service
public class OtpService {
    private ConcurrentHashMap<String, String> otpMap = new ConcurrentHashMap<>();
    public void generateOtp(String aadhaar) {
        // TODO: Generate a 6-digit OTP and store it in otpMap
    }
    public boolean validateOtp(String aadhaar, String otp) {
        // TODO: Validate OTP from otpMap
        return false; // Placeholder
    }
}