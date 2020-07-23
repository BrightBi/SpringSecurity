package com.bi.security.decision;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Service;
/**
 * FilterInvocationSecurityMetadataSource 的作用是用来储存请求与权限的对应关系，它有3个方法：
 * 1. supports(Class<?> clazz)：指示该类是否能够为指定的方法调用或Web请求提供ConfigAttributes。
 * 2. getAllConfigAttributes()：Spring 容器启动时自动调用, 
 *    一般把所有请求与权限的对应关系也要在这个方法里初始化, 保存在一个属性变量里。
 * 3. getAttributes(Object object)：当接收到一个http请求时, filterSecurityInterceptor 会调用的方法. 
 *    参数object是一个包含 url 信息的 HttpServletRequest 实例. 这个方法要返回请求该 url 所需要的所有权限集合。
 */
@Service
public class MyInvocationSecurityMetadataSourceService implements FilterInvocationSecurityMetadataSource {

	// 每一个资源所需要的角色 Collection<ConfigAttribute>，决策器 MyAccessDecisionManager 会用到
	private HashMap<String, Collection<ConfigAttribute>> map = null;

	// 加载自己权限表中所配置的自定义权限权限。 比如我配置 /security/self 路径需要有 MASTER ADMIN 权限。
	public void loadResourceDefine() {
		map = new HashMap<>();
		Collection<ConfigAttribute> configMusterAdmin = new ArrayList<>();
		Collection<ConfigAttribute> configUser = new ArrayList<>();
		ConfigAttribute attributeMaster = new SecurityConfig("MUSTER");
		ConfigAttribute attributeAdmin = new SecurityConfig("ADMIN");
		ConfigAttribute attributeUser = new SecurityConfig("USER");
		// 此处添加的信息将会作为 MyAccessDecisionManager 类的 decide 的第三个参数。
		configMusterAdmin.add(attributeMaster);
		configMusterAdmin.add(attributeAdmin);
		configUser.add(attributeUser);
		// 用权限的 getUrl() 作为 map 的 key，用 ConfigAttribute 的集合作为 value，
		map.put("/security/muster-admin", configMusterAdmin);
		map.put("/security/user", configUser);
	}

	// 此方法是为了判定用户请求的 url 是否在权限表中，如果在权限表中，则返回给 decide 方法，用来判定用户是否有此权限。如果不在权限表中则放行。
	@Override
	public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
		if (map == null)
			loadResourceDefine();
		// object 中包含用户请求的request 信息
		HttpServletRequest request = ((FilterInvocation) object).getHttpRequest();
		AntPathRequestMatcher matcher;
		String resUrl;
		for (Iterator<String> iter = map.keySet().iterator(); iter.hasNext();) {
			resUrl = iter.next();
			matcher = new AntPathRequestMatcher(resUrl);
			if (matcher.matches(request)) {
				return map.get(resUrl);
			}
		}
		return null;
	}

	@Override
	public Collection<ConfigAttribute> getAllConfigAttributes() {
		return null;
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return true;
	}
}
