package com.wsomad.Authentication.service;

import com.wsomad.Authentication.model.DTO.AuthRequest;
import com.wsomad.Authentication.model.DTO.AuthResponse;
import com.wsomad.Authentication.model.User;
import com.wsomad.Authentication.repository.UserRepository;
import com.wsomad.Authentication.util.JWTUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTUtil jwtUtil;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, JWTUtil jwtUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    public void register(AuthRequest request) {
        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setEmail(request.getEmail());
        user.setRole(request.getRole());

        userRepository.save(user);
    }

    public AuthResponse authenticateUser(AuthRequest request) {
        // Find user by username
        User user = userRepository
                .findByUsername(request.getUsername()).orElseThrow(() -> new RuntimeException("User not found"));

        // PasswordEncoder is a security component that transforms plain text password into a secure format.
        // So, it takes the password entered by user then hashed it to be compared to the password stored in DB.
        if(!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid password");
        }

        // Pass the user object to generate token
        String token = jwtUtil.generateToken(user);

        // Then, return the generated token
        return new AuthResponse(token);
    }

    public User getCurrentUserDetails(HttpServletRequest request) {
        String token = jwtUtil.extractToken(request);
        Long userId = jwtUtil.extractSubject(token);

        return userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
    }
}
