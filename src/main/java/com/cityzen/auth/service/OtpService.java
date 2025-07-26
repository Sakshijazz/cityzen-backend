package com.cityzen.auth.service;
import org.springframework.stereotype.Service;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
@Service
public class OtpService {
    private ConcurrentHashMap<String, String> otpMap = new ConcurrentHashMap<>();
    public String generateOtp(String aadhaar) {
        // Generate a 6-digit OTP
        String otp = String.valueOf(new Random().nextInt(900000) + 100000); // Generates a random 6-digit OTP
        otpMap.put(aadhaar, otp); // Store the OTP in the map with Aadhaar as the key
        return otp; // Return the generated OTP
    }
    public boolean validateOtp(String aadhaar, String otp) {
        // Validate OTP from otpMap
        String storedOtp = otpMap.get(aadhaar); // Retrieve the stored OTP using Aadhaar
        return storedOtp != null && storedOtp.equals(otp); // Check if the provided OTP matches the stored OTP
    }
}