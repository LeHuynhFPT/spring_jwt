package com.example.spring_jwt.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtResponse {
    private String username;
    private String token;
    private String tokeType = "Bearer";

    public JwtResponse(String username , String token) {
        this.username = username;
        this.token = token;
    }
}
