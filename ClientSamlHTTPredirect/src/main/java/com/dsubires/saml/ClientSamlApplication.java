package com.dsubires.saml;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
//@EnableScheduling
/**
 * 
 * 
 * @author David Subires
 *
 */
public class ClientSamlApplication {

	public static void main(String[] args) {
		SpringApplication.run(ClientSamlApplication.class, args);
	}

}
