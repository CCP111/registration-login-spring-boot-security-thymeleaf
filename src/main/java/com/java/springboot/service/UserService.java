package com.java.springboot.service;

import org.springframework.security.core.userdetails.UserDetailsService;

import com.java.springboot.model.User;
import com.java.springboot.web.dto.UserRegistrationDto;

public interface UserService extends UserDetailsService {
	User save(UserRegistrationDto registrationDto);
}
