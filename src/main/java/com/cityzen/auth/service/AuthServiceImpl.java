package com.cityzen.auth.service;
import com.cityzen.auth.dto.*;
import com.cityzen.auth.entity.ForgotPasswordToken;
import com.cityzen.auth.entity.User;
import com.cityzen.auth.enums.Role;
import com.cityzen.auth.exception.CustomException;
import com.cityzen.auth.repository.ForgotPasswordTokenRepository;
import com.cityzen.auth.repository.UserRepository;
import com.cityzen.auth.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
//Dont remove this annotation(Primary)
@Primary
public class AuthServiceImpl implements AuthService, UserDetailsService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private ForgotPasswordTokenRepository forgotPasswordTokenRepository;
    // In-memory OTP storage (for simplicity, consider using a more robust solution)
    private final Map<String, String> otpStore = new ConcurrentHashMap<>();
    private static final Set<String> mockAadhaarSet = new HashSet<>(Arrays.asList(
            "123456789012",// Add some mock Aadhaar numbers for testing
            "987654321012"
    ));

    @Override
    public String generateOtp(String aadhaar) {
        // Generate a 6-digit OTP and store it in otpStore
        String otp = String.valueOf(new Random().nextInt(900000) + 100000); // Generate 6-digit OTP
        otpStore.put(aadhaar, otp);
        return otp; // Return OTP for testing purposes
    }

    @Override
    public boolean validateOtp(String aadhaar, String otp) {
        // Validate OTP against the stored value in otpStore
        String storedOtp = otpStore.get(aadhaar);
        return storedOtp != null && storedOtp.equals(otp);
    }

    @Override
    public void signup(SignUpRequest request) {
        // Validate that the user does not already exist
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new CustomException("User already exists", HttpStatus.BAD_REQUEST);
        }
        User user = new User();
        user.setUserName(request.getUserName());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword())); // Hash the password
        user.setRole(Role.CITIZEN); // Set default role
        userRepository.save(user);
    }

    @Override
    public JwtResponse signin(SignInRequest request) {
        // Authenticate user and return JWT
        Optional<User> userOpt = userRepository.findByEmail(request.getEmail());
        if (userOpt.isPresent() && passwordEncoder.matches(request.getPassword(), userOpt.get().getPassword())) {
            String token = jwtUtil.generateToken(userOpt.get().getEmail(), userOpt.get().getRole().name());
            return new JwtResponse(token, userOpt.get().getRole().name(), userOpt.get().getEmail(), System.currentTimeMillis() + 3600000);
        } else {
            throw new CustomException("Invalid credentials", HttpStatus.UNAUTHORIZED);
        }
    }

    @Override
    public void forgotPassword(ForgotPasswordRequest request) {
        // Generate a reset token and save it to the database
        Optional<User> userOpt = userRepository.findByEmail(request.getEmail());
        if (userOpt.isPresent()) {
            String token = UUID.randomUUID().toString(); // Generate a unique reset token
            ForgotPasswordToken forgotPasswordToken = new ForgotPasswordToken();
            forgotPasswordToken.setEmail(request.getEmail());
            forgotPasswordToken.setToken(token);
            forgotPasswordToken.setExpiryDate(LocalDateTime.now().plusHours(1)); // Set expiry time for the token
            forgotPasswordTokenRepository.save(forgotPasswordToken);
            // TODO: Send email with the reset token link (implement email service)
        } else {
            throw new CustomException("Email not found", HttpStatus.NOT_FOUND);
        }
    }

    @Override
    public void resetPassword(ResetPasswordRequest request) {
        // Validate the reset token and reset the password
        Optional<ForgotPasswordToken> tokenOpt = forgotPasswordTokenRepository.findByToken(request.getToken());
        if (tokenOpt.isPresent() && tokenOpt.get().getExpiryDate().isAfter(LocalDateTime.now())) {
            Optional<User> userOpt = userRepository.findByEmail(tokenOpt.get().getEmail());
            if (userOpt.isPresent()) {
                User user = userOpt.get();
                user.setPassword(passwordEncoder.encode(request.getNewPassword())); // Hash the new password
                userRepository.save(user); // Save the updated user
                forgotPasswordTokenRepository.delete(tokenOpt.get()); // Delete the token after use
            } else {
                throw new CustomException("User not found", HttpStatus.NOT_FOUND);
            }
        } else {
            throw new CustomException("Invalid or expired token", HttpStatus.BAD_REQUEST);
        }
    }

    @Override
    public void changePassword(ChangePasswordRequest request) {
        // Assume you have a way to get the currently logged-in user's email
        String currentUserEmail = "current_user@example.com"; // Replace with actual current user context
        Optional<User> userOpt = userRepository.findByEmail(currentUserEmail);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            // Validate the current password
            if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
                throw new CustomException("Current password is incorrect", HttpStatus.UNAUTHORIZED);
            }
            // Update to the new password
            user.setPassword(passwordEncoder.encode(request.getNewPassword())); // Hash the new password
            userRepository.save(user); // Save the updated user
        } else {
            throw new CustomException("User not found", HttpStatus.NOT_FOUND);
        }
    }

    @Override
    public boolean verifyAadhaar(String aadhaar) {
        // Check if the Aadhaar number exists in the mock dataset
        return mockAadhaarSet.contains(aadhaar);
    }

//    @Override
//    public boolean verifyAadhaar(String aadhaar) {
//        // TODO: Implement logic to check if the Aadhaar number exists in the database
//        // For example, you might want to check against a mock database or a real database
//        return aadhaarRegistryRepository.findByAadhaarNumber(aadhaar).isPresent(); // Example logic
//    }

    //Dont Remove this method
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Load user by username (email in this case)
        Optional<User> userOpt = userRepository.findByEmail(username);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), new ArrayList<>()); // You can add roles and authorities if needed
        } else {
            throw new UsernameNotFoundException("User not found with email: " + username);
        }
    }
}









