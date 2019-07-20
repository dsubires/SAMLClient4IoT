package com.dsubires.saml;

public class Main {

	public static void main(String[] args) {
		ClientHTTPRedirect client = new ClientHTTPRedirect();

		client.setHost("192.168.1.168");
		client.setClientID("Baria");
		client.setServerID("Alice");
		client.setSpURL("https://" + client.getHost() + "/test.php");

		for (int i = 0; i <= 10; i++) {
			client.getResource();
		}

	}

}
