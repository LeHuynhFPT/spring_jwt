package com.example.spring_jwt.service;

import com.example.spring_jwt.entity.User;
import com.example.spring_jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    public boolean createAccount(User user) {
        try {
            userRepository.save(user);
            return true;
        }catch (Exception ex) {
            System.out.println(ex.getMessage());
            return  false;
        }
    }

    public User findUserByUsername(String username) {
        return userRepository.findUserByUsername(username);
    }
}
