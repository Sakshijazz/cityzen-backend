package com.cityzen.auth.repository;
import com.cityzen.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    // Method to find user by Aadhaar number
    Optional<User> findByAadhaar(String aadhaar);

}