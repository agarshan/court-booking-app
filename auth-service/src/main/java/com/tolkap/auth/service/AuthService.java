package com.tolkap.auth.service;

import com.tolkap.auth.dto.AuthRequest;
import com.tolkap.auth.dto.RegisterRequest;
import com.tolkap.auth.model.Role;
import com.tolkap.auth.model.User;
import com.tolkap.auth.repository.UserRepository;
import com.tolkap.auth.security.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepo;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private JwtService jwtService;

    public String register(RegisterRequest request) {
        if (userRepo.existsByEmail(request.getEmail()))
            throw new RuntimeException("Email already exists");

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.USER);

        userRepo.save(user);

        return jwtService.generateToken(user);
    }

    public String authenticate(AuthRequest request) {
        User user = userRepo.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Invalid credentials"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword()))
            throw new RuntimeException("Invalid credentials");

        return jwtService.generateToken(user);
    }
}

