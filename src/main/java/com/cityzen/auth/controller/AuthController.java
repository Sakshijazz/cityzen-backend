package com.cityzen.auth.controller;
import com.cityzen.auth.dto.*;
import com.cityzen.auth.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthService authService;
    @PostMapping("/verify-aadhaar")
    public ResponseEntity<?> verifyAadhaar(@RequestBody AadhaarVerifyRequest request) {
        // TODO: Check mock DB and generate 6-digit OTP
        return ResponseEntity.ok().build();
    }
    @PostMapping("/validate-otp")
    public ResponseEntity<?> validateOtp(@RequestBody AadhaarVerifyRequest request) {
        // TODO: Validate OTP for Aadhaar
        return ResponseEntity.ok().build();
    }
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody SignUpRequest request) {
        // TODO: Register new citizen (OTP must be validated first)
        return ResponseEntity.ok().build();
    }
    @PostMapping("/signin")
    public ResponseEntity<?> signin(@RequestBody SignInRequest request) {
        // TODO: Authenticate and return JWT
        return ResponseEntity.ok().build();
    }
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        // TODO: Generate and save reset token
        return ResponseEntity.ok().build();
    }
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest request) {
        // TODO: Reset password using token
        return ResponseEntity.ok().build();
    }
    @PutMapping("/change-password")
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest request) {
        // TODO: Allow logged-in users to update password
        return ResponseEntity.ok().build();
    }
}