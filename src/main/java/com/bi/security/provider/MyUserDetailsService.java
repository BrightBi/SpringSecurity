package com.bi.security.provider;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import com.bi.security.util.MyUser;
import com.bi.security.util.Tool;

@Component
public class MyUserDetailsService implements UserDetailsService {

	@Override
	public UserDetails loadUserByUsername(String username) {
		System.out.println("MyUserDetailsService loadUserByUsername : " + username);
		MyUser user = Tool.getUser(username);
		if (user == null) {
			return null;
		}
		return user;
	}
}
