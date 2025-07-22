package com.cityzen.auth.repository;
import com.cityzen.auth.entity.ForgotPasswordToken;
import org.springframework.data.jpa.repository.JpaRepository;
public interface ForgotPasswordTokenRepository extends JpaRepository<ForgotPasswordToken, Long> {
    // TODO: Find token by string
    // TODO: Delete after reset or expiration
}