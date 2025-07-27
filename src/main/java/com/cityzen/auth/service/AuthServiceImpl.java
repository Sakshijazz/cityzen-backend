package com.cityzen.auth.service;

import com.cityzen.auth.dto.*;
import com.cityzen.auth.entity.User;
import com.cityzen.auth.enums.Role;
import com.cityzen.auth.repository.AadhaarRegistryRepository;
import com.cityzen.auth.repository.UserRepository;
import com.cityzen.auth.util.JwtUtil;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@Primary
public class AuthServiceImpl implements AuthService {

    @Autowired
    private AadhaarRegistryRepository aadhaarRegistryRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    private boolean isValidPassword(String password) {
        return password != null && password.matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*#?&]).{8,}$");
    }

    @Override
    public boolean verifyAadhaar(String aadhaar) {
        return aadhaarRegistryRepository.findByAadhaarNumber(aadhaar).isPresent();
    }


    @Override
    public void signup(SignUpRequest request) {
        if (!isValidPassword(request.getPassword())) {
            throw new IllegalArgumentException("Password must be strong (8+ chars with uppercase, lowercase, digit, special char)");
        }

        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email already in use");
        }

        if (userRepository.findByAadhaar(request.getAadhaar()).isPresent()) {
            throw new IllegalArgumentException("Aadhaar already registered");
        }

        User user = new User();
        user.setUserName(request.getUserName());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setAadhaar(request.getAadhaar());
        user.setRole(Role.CITIZEN);

        userRepository.save(user);
    }

    @Override
    public JwtResponse signin(SignInRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + request.getEmail()));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Invalid password");
        }

        String token = jwtUtil.generateToken(user.getEmail(), user.getRole().name());
        return new JwtResponse(
                token,
                user.getRole().name(),
                user.getEmail(),
                System.currentTimeMillis() + 3600000 // 1 hour expiry (or whatever you're using)
        );

    }

    @Override
    public JwtResponse generateJwtResponse(Authentication authentication) {
        String email = authentication.getName(); // extract email from Authentication
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

        String token = jwtUtil.generateToken(user.getEmail(), user.getRole().name());
        return new JwtResponse(
                token,
                user.getRole().name(),
                user.getEmail(),
                System.currentTimeMillis() + 3600000
        );

    }

    @Override
    public void forgotPassword(ForgotPasswordRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + request.getEmail()));

        String newPassword = UUID.randomUUID().toString().substring(0, 8);
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        // Email sending logic in controller or separate email service
    }

    @Override
    public void resetPassword(ResetPasswordRequest request) {
        String email = jwtUtil.extractUsername(request.getToken());
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

        if (!isValidPassword(request.getNewPassword())) {
            throw new IllegalArgumentException("Password does not meet strength requirements");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }

    @Override
    @Transactional
    public void changePassword(ChangePasswordRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + request.getEmail()));

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Incorrect current password");
        }

        if (!isValidPassword(request.getNewPassword())) {
            throw new IllegalArgumentException("Password must meet strength requirements");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }
}
