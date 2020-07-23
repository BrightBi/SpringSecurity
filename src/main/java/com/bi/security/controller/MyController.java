package com.bi.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("/security")
public class MyController {

	// http://localhost:8080/security/hi
	@RequestMapping("/hi")
	public String hi() {
		System.out.println("SecurityController.hi");
		return "loginout";
	}

	// http://localhost:8080/security/self
	@RequestMapping("/self")
	public @ResponseBody String selfPermision() {
		System.out.println("MyController.selfPermision");
		return "MyController.selfPermision";
	}

	// http://localhost:8080/security/muster-admin
	@RequestMapping("/muster-admin")
	public @ResponseBody String musterAdmin() {
		System.out.println("MyController.musterAdmin");
		return "MyController.musterAdmin";
	}

	// http://localhost:8080/security/user
	@RequestMapping("/user")
	public @ResponseBody String user() {
		System.out.println("MyController.user");
		return "MyController.user";
	}

	// http://localhost:8080/security/login
	@RequestMapping("/signin")
	public String login() {
		return "signin-form";
	}

	@RequestMapping("/401")
	public String accessDenied() {
		return "401";
	}
}
