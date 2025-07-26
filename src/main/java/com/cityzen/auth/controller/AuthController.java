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
        // Verify the Aadhaar number
        boolean isVerified = authService.verifyAadhaar(request.getAadhaar());
        if (isVerified) {
            return ResponseEntity.ok("Aadhaar number is verified.");
        } else {
            return ResponseEntity.badRequest().body("Aadhaar number not found.");
        }
    }

    @PostMapping("/validate-otp")
    public ResponseEntity<?> validateOtp(@RequestBody ValidateOtpRequest request) {
        // Validate the OTP against the generated OTP
        return null;
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody SignUpRequest request) {
        // Proceed with signup after OTP verification
        authService.signup(request);
        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/signin")
    public ResponseEntity<?> signin(@RequestBody SignInRequest request) {
        // Authenticate user and return JWT token
        JwtResponse jwtResponse = authService.signin(request);
        return ResponseEntity.ok(jwtResponse);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        // Generate and save reset token, send email to user
        authService.forgotPassword(request);
        return ResponseEntity.ok("Password reset email sent");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest request) {
        // Reset password using the provided token
        authService.resetPassword(request);
        return ResponseEntity.ok("Password reset successfully");
    }

    @PutMapping("/change-password")
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest request) {
        // Allow logged-in users to update their password
        authService.changePassword(request);
        return ResponseEntity.ok("Password changed successfully");
    }
}




