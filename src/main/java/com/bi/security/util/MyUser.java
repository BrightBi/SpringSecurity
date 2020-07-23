package com.bi.security.util;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class MyUser implements UserDetails {
	private static final long serialVersionUID = -3818865218535257048L;
	private String username;
	private String password;
	private boolean enabled = true;

	@Override
	public boolean isAccountNonExpired() { // 帐户是否过期
		return true;
	}

	@Override
	public boolean isAccountNonLocked() { // 帐户是否被冻结
		return true;
	}

	// 帐户密码是否过期，一般有的密码要求性高的系统会使用到，比较每隔一段时间就要求用户重置密码
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() { // 帐号是否可用
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	@Override
	public List<GrantedAuthority> getAuthorities() {
		List<GrantedAuthority> authorities = new ArrayList<>();
		authorities.add(new SimpleGrantedAuthority("ADMIN"));
		return authorities;
	}

	public MyUser(String username, String password) {
		this.username = username;
		this.password = password;
	}

	@Override
	public String getPassword() {
		return this.password;
	}
	
	public void setPassword(String password) {
		this.password = password;
	}

	@Override
	public String getUsername() {
		return this.username;
	}
}
