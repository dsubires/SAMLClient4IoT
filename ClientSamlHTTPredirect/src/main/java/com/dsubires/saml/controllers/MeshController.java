package com.dsubires.saml.controllers;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.dsubires.saml.models.MeshPetition;
import com.dsubires.saml.services.ClientSamlService;

/**
 * Clase que define el controlador de las funciones mesh. Mediante este
 * controlador se interactúa con el servicio web REST de cada dispositivo
 * (sensor) de la red.
 *
 */

@RestController
@CrossOrigin
@RequestMapping(value = "/mesh", produces = MediaType.APPLICATION_JSON_VALUE)
public class MeshController {

	@Autowired
	private ClientSamlService clientService;
	private Logger logger = LogManager.getLogger("mesh-controller");
	@Value("${mesh.authcode}")
	private String meshAuthcode;

	/**
	 * Endpoint que recibe de otro dispositivo una petición mesh para reenviarla al
	 * servicio web intermedio a Elasticsearch
	 * 
	 * @param meshPetition Petición mesh. Incluye código de autenticación y datos
	 *                     del dispositivo para reenviar.
	 * @return Devuelve cadena de texto informando si la operación se realizó
	 *         correctamente o no.
	 */
	@RequestMapping(value = "/forward", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
	public String forward(@RequestBody MeshPetition meshPetition) {

		if (meshPetition != null && meshAuthcode.equals(meshPetition.getAuthcode())) {
			clientService.sendDeviceStatus(meshPetition.getDeviceStatus());
			logger.info("deviceStatus forwarded successfully");
			return "{\n\r\"msg\" : \"deviceStatus forwarded successfully\" }";
		} else {
			return "{\n\r\"error\" : \"authcode error\" \r\n}";
		}
	}

	/**
	 * Endpoint implementado para realizar pruebas sobre el servicio
	 * 
	 * @return hello world
	 */
	@RequestMapping(value = "/test", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
	public String matchRequest() {
		logger.info("hello world");
		return "{\n\r \"Hello\" :  \"world\"\n}";
	}

}
