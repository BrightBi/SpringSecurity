package com.bi.security.provider;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

@Component
public class RemoteAuthProvider implements AuthenticationProvider {
	private static Map<String, String> users = new HashMap<>();	
	static { users.put("liang", "liang"); }

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String username = (authentication.getPrincipal() == null) ? "NONE_PROVIDED" : authentication.getName();
		String password = (String) authentication.getCredentials();
		System.out.println("RemoteAuthProvider authenticate : " + username + "|" + password);
		if (!users.containsKey(username)) {
			System.out.println(this.getClass().getName() + " return null");
			return null;
		}
		if (password == null) {
			throw new BadCredentialsException("密码不能为空");
		}
		if (!password.equals(users.get(username))) {
			throw new BadCredentialsException("用户名或密码不正确");
		}
		UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(username, password,
				listGrantedAuthorities());
		result.setDetails(authentication.getDetails());
		return result;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		System.out.println(this.getClass().getName() + " supports:" + UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
		return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
	}

	private Set<GrantedAuthority> listGrantedAuthorities() {
		Set<GrantedAuthority> authorities = new HashSet<GrantedAuthority>();
		authorities.add(new SimpleGrantedAuthority("USER"));
		return authorities;
	}

}
