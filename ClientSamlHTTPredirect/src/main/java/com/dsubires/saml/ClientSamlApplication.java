package com.dsubires.saml;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
/**
 * Clase principal del proyecto. Inicia la aplicación Spring y todos sus
 * servicios. La aplicación permite acceder a recursos protegidos por SAML, tras
 * realizar la autenticación adaptada a dispositivos.
 * 
 * @author David Subires Parra
 *
 */
public class ClientSamlApplication {

	public static void main(String[] args) {
		SpringApplication.run(ClientSamlApplication.class, args);
	}

}
