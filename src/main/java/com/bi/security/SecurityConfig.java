package com.bi.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;

import com.bi.security.filter.SelfAuthenticationFilter;
import com.bi.security.handler.AuthFailHandler;
import com.bi.security.handler.AuthSuccessHandler;
import com.bi.security.provider.MobileAuthProvider;
import com.bi.security.provider.MyUserDetailsService;
import com.bi.security.provider.RemoteAuthProvider;
import com.bi.security.provider.UserAuthProvider;
import com.bi.security.util.MyPasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private UserAuthProvider userAuthProvider;
	@Autowired
	private MobileAuthProvider mobileAuthProvider;
	@Autowired
	private RemoteAuthProvider remoteAuthProvider;
	@Autowired
	AuthSuccessHandler authSuccessHandler;
	@Autowired
	AuthFailHandler authFailHandler;
	@Autowired
	MyUserDetailsService myUserDetailsService;
	@Autowired
	MyPasswordEncoder myPasswordEncoder;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.addFilterAt(selfAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
			.authorizeRequests().antMatchers("/security/self").authenticated().anyRequest().permitAll().and()
			/*
			 * loginPage() 指定登陆页面的 url，就是要输入用户名和密码的页面路径。
			 * 这里的 /security/signin 会映射到 MyController 的 @RequestMapping("/signin")，
			 * 由于其返回 signin-form，最终会展示给用户 signin-form.html 这个页面。
			 * 
			 * usernameParameter() passwordParameter() 对 signin-form.html 中的用户名跟密码进行映射，
			 * 以用户名为例：<input type="text" name="un"/>
			 * name="un" 要与 usernameParameter("un") 一致。
			 * 否则 Spring 默认去取以 username/password 为参数名的值做为用户名和密码，会取不到值。
			 * 也可以将 signin-form.html 中的用户名跟密码设置成 username/password，
			 * 这样就不用再设置 usernameParameter("username").passwordParameter("password")。
			 * Spring 取默认值就能取到。
			 * 
			 * loginProcessingUrl() 指定用来处理提交的用户名密码 URL。
			 * signin-form.html 这个页面配置的 <form th:action="@{/security/login}" method="post">
			 * 表示要将用户名和密码提交到 /security/login 这个路径上。
			 * 所以这里要提供 loginProcessingUrl 来处理提交的用户名和密码。
			 * 如果将用户名和密码的提交路径改为 /security/signin，即，跟 loginPage("/security/signin") 相同，
			 * 那么可以省略 loginProcessingUrl("/security/signin")
			 */
			.formLogin().loginPage("/security/signin").loginProcessingUrl("/security/login").permitAll().and()
			.exceptionHandling().accessDeniedPage("/security/401").and()
			.logout().logoutSuccessUrl("/security/signin").permitAll().and()
			.rememberMe().rememberMeCookieName("my-remember-me-cookie").key("testallKey").and()
			.csrf().disable();
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(mobileAuthProvider)
			.authenticationProvider(userAuthProvider)
			.authenticationProvider(remoteAuthProvider)
			.userDetailsService(myUserDetailsService).passwordEncoder(myPasswordEncoder);
	}

	@Bean
	public SelfAuthenticationFilter selfAuthenticationFilter() throws Exception {
		SelfAuthenticationFilter filter = new SelfAuthenticationFilter();
		filter.setAuthenticationManager(authenticationManagerBean());
		filter.setAuthenticationSuccessHandler(authSuccessHandler);
		filter.setAuthenticationFailureHandler(authFailHandler);
		filter.setRememberMeServices(tokenBasedRememberMeServices());
		return filter;
	}
	
	@Bean
    public TokenBasedRememberMeServices tokenBasedRememberMeServices() {
        TokenBasedRememberMeServices tbrms = new TokenBasedRememberMeServices("testallKey", myUserDetailsService);
        // 设置cookie过期时间(单位是秒)，此处为3分钟
        tbrms.setTokenValiditySeconds(60 * 10);
        /*
         * 设置 checkbox 的参数名为 self-remember-me（默认为remember-me），
         * 如果是 ajax 请求，参数名不是 checkbox 的 name 而是在 ajax 的 data 里
         */
        tbrms.setParameter("self-remember-me");
        // 定义存在 客户端的 cookie 名字
        tbrms.setCookieName("my-remember-me-cookie");
        return tbrms;
    }
}
