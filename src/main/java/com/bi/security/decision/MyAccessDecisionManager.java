package com.bi.security.decision;

import java.util.Collection;
import java.util.Iterator;

import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
/**
 * MyAccessDecisionManager 类实现了 AccessDecisionManager 接口，AccessDecisionManager 是由 AbstractSecurityInterceptor 调用的，
 * 它负责鉴定用户是否有访问对应资源（方法或URL）的权限。
 */
@Service
public class MyAccessDecisionManager implements AccessDecisionManager {
	/*
	 *  decide 方法是判定是否拥有权限的决策方法，
	 *  authentication 是 CustomUserService 中循环添加到 GrantedAuthority 对象中的权限信息集合.
	 *  object 包含客户端发起的请求的 request 信息，可转换为 HttpServletRequest request = ((FilterInvocation) object).getHttpRequest();
	 *  configAttributes 为 MyInvocationSecurityMetadataSource 的 getAttributes(Object object)这个方法返回的结果，
	 *  此方法是为了判定用户请求的 url 是否在权限表中，如果在权限表中，则返回给 decide 方法，用来判定用户是否有此权限。如果不在权限表中则放行。
	 */
	@Override
	public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes)
			throws AccessDeniedException, InsufficientAuthenticationException {

		if (null == configAttributes || configAttributes.size() <= 0) {
			return;
		}
		ConfigAttribute c;
		String needRole;
		for (Iterator<ConfigAttribute> iter = configAttributes.iterator(); iter.hasNext();) {
			c = iter.next();
			needRole = c.getAttribute();
			// authentication 为在 CustomUserService 中循环添加到 GrantedAuthority 对象中的权限信息集合
			for (GrantedAuthority authority : authentication.getAuthorities()) {
				if (needRole.trim().equals(authority.getAuthority())) {
					return;
				}
			}
		}
		throw new AccessDeniedException("MyAccessDecisionManager: No right");
	}

	// 表示此 AccessDecisionManager 是否能够处理传递的 ConfigAttribute 呈现的授权请求
	@Override
	public boolean supports(ConfigAttribute attribute) {
		return true;
	}

	// 表示当前 AccessDecisionManager 实现是否能够为指定的安全对象（方法调用或Web请求）提供访问控制决策
	@Override
	public boolean supports(Class<?> clazz) {
		return true;
	}
}
