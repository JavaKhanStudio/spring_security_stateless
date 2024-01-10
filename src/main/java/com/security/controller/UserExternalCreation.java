package com.security.controller;

import com.security.dto.LoginDTO;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users/external")
public class UserExternalCreation {

    @PostMapping("/create/students")
    public ResponseEntity<?> loginUser(@RequestBody LoginDTO loginDto) {
        return ResponseEntity.ok("User registered successfully");
    }


}
