package com.bi.security.util;

import java.util.HashMap;
import java.util.Map;

public class Tool {
	
	private static Map<String, MyUser> users = new HashMap<>();

	public static MyUser getUser(String name) {
		if (users.size() < 1) {
			initUsers();
		}
		return users.get(name);
	}
	
	public static void initUsers() {
		MyUser bi = new MyUser("bi", "bi");
		MyUser ming = new MyUser("ming", "ming");
		MyUser liang = new MyUser("liang", "liang");
		MyUser bright = new MyUser("bright", "bright");

		users.put(bi.getUsername(), bi);
		users.put(ming.getUsername(), ming);
		users.put(liang.getUsername(), liang);
		users.put(bright.getUsername(), bright);
	}
}
