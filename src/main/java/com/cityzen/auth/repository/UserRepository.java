package com.cityzen.auth.repository;
import com.cityzen.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    Optional<User> findByEmailAndRole(String email, String role);
    // TODO: Optional: check if Aadhaar already exists
}