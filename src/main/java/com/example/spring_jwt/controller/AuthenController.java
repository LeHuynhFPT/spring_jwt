package com.example.spring_jwt.controller;

import com.example.spring_jwt.dto.UserDTO;
import com.example.spring_jwt.entity.User;
import com.example.spring_jwt.response.JwtResponse;
import com.example.spring_jwt.service.UserService;
import com.example.spring_jwt.service.jwt.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("")
public class AuthenController {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserService userService;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody UserDTO userDTO) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(userDTO.getUsername(), userDTO.getPassword())
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String token = jwtService.generateToken(authentication);
            return ResponseEntity.ok().body(new JwtResponse(userDTO.getUsername(), token));

        } catch (Exception exception) {
            System.out.println(exception.getMessage());
        }
        return ResponseEntity.ok().body("Tên đăng nhập hoặc mật khẩu không đúng");
    }

    @PostMapping("/register")
    public String register(@RequestBody UserDTO userDTO) {
        try {
            if (userService.findUserByUsername(userDTO.getUsername()) != null) {
                return "Tên người dùng đã tồn tại, vui lòng chọn một tên người dùng khác";
            }
            User user = new User();
            user.setUsername(userDTO.getUsername());
            user.setPassword(bCryptPasswordEncoder.encode(userDTO.getPassword()));
            user.setRoles(new HashSet<>());
            userService.createAccount(user);
            return "Tạo tài khoản thành công";

        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
        return "Đăng ký không thành công";
    }
}
