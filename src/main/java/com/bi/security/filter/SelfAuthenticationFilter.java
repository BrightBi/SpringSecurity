package com.bi.security.filter;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.bi.security.token.MobileAuthToken;

public class SelfAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	public static final String USER_NAME = "username";
	public static final String PASSWORD = "password";
	public static final String AUTYPE = "autype";

	public SelfAuthenticationFilter() {
		super(new AntPathRequestMatcher("/security/login", "POST"));
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		if (!request.getMethod().equals("POST")) {
			throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
		}

		String username = request.getParameter(USER_NAME);
		String password = request.getParameter(PASSWORD);
		String autype = request.getParameter(AUTYPE);
		System.out.println(this.getClass().getName() + " autype:" + autype);

		if (username == null) {
			username = "";
		}

		if (password == null) {
			password = "";
		}

		if (autype == null) {
			autype = "";
		}

		// 对用户密码进行加密，不要在网络中传递明文密码
		// password = "x-" + password;

		AbstractAuthenticationToken authRequest = null;
		if ("m".equals(autype)) {
			MobileAuthToken mAuthRequest = new MobileAuthToken(username, password);
			mAuthRequest.setAutype(autype);
			authRequest = mAuthRequest;
		} else {
			authRequest = new UsernamePasswordAuthenticationToken(username, password);
		}
		// Allow subclasses to set the "details" property
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
		return this.getAuthenticationManager().authenticate(authRequest);
	}
}
