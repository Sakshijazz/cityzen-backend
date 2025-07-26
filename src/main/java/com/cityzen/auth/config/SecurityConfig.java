package com.cityzen.auth.config;

import com.cityzen.auth.filter.JwtAuthenticationFilter;
import com.cityzen.auth.repository.AadhaarRegistryRepository;
import com.cityzen.auth.repository.ForgotPasswordTokenRepository;
import com.cityzen.auth.repository.UserRepository;
import com.cityzen.auth.service.AuthServiceImpl;
import com.cityzen.auth.util.JwtUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/auth/signup", "/auth/signin", "/auth/verify-aadhaar").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

//    @Bean
//    public AuthServiceImpl userDetailsService(
//            UserRepository userRepository,
//            PasswordEncoder passwordEncoder,
//            JwtUtil jwtUtil,
//            AuthenticationManager authenticationManager,
//            ForgotPasswordTokenRepository forgotPasswordTokenRepository,
//            AadhaarRegistryRepository aadhaarRegistryRepository
//    ) {
//        return new AuthServiceImpl(
//                userRepository,
//                passwordEncoder,
//                jwtUtil,
//                authenticationManager,
//                forgotPasswordTokenRepository,
//                aadhaarRegistryRepository
//        );
//    }
}