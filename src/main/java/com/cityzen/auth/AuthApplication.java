package com.cityzen.auth;
import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
@SpringBootApplication
public class AuthApplication {
    public static void main(String[] args) {
        Dotenv dotenv = Dotenv.load();
        SpringApplication.run(AuthApplication.class, args);
        System.out.println("Server started");
    }
}