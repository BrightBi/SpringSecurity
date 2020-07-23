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

import com.bi.security.token.MobileAuthToken;

@Component
public class MobileAuthProvider implements AuthenticationProvider {
	private static Map<String, String> users = new HashMap<>();	
	static { users.put("ming", "ming"); }
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		MobileAuthToken mAuthRequest = (MobileAuthToken) authentication;
		String mobile = (mAuthRequest.getPrincipal() == null) ? "NONE_PROVIDED" : mAuthRequest.getName();
		String code = (String) mAuthRequest.getCredentials();
		if (!users.containsKey(mobile)) {
			throw new BadCredentialsException("用户不存在");
		}
		if (code == null) {
			throw new BadCredentialsException("验证码不能为空");
		}
		if (!code.equals(users.get(mobile))) {
			throw new BadCredentialsException("账户或密码不正确，登陆失败。");
		}
		UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(mobile, code,
				listGrantedAuthorities());
		result.setDetails(mAuthRequest.getDetails());
		return result;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		System.out.println(this.getClass().getName() + " supports:" + MobileAuthToken.class.isAssignableFrom(authentication));
		return (MobileAuthToken.class.isAssignableFrom(authentication));
	}

	private Set<GrantedAuthority> listGrantedAuthorities() {
		Set<GrantedAuthority> authorities = new HashSet<GrantedAuthority>();
		authorities.add(new SimpleGrantedAuthority("ADMIN"));
		return authorities;
	}
}
