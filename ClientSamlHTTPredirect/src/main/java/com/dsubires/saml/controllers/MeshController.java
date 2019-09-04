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
import com.dsubires.saml.services.ClientService;

@RestController
@CrossOrigin
@RequestMapping(value = "/mesh", produces = MediaType.APPLICATION_JSON_VALUE)
public class MeshController {

	@Autowired
	private ClientService clientService;
	private Logger logger = LogManager.getLogger("mesh-controller");
	@Value("${mesh.authcode}")
	private String meshAuthcode;


	@RequestMapping(value = "/test", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
	public String matchRequest() {
		logger.info("hello world");
		return "{ \"Hello\" :  \"world\" }";
	}
	
	@RequestMapping(value = "/forward", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
	public String forward(@RequestBody MeshPetition meshPetition) {
		
		if(meshPetition != null && meshAuthcode.equals(meshPetition.getAuthcode())) {
			clientService.sendDeviceStatus(meshPetition.getDeviceStatus());
			logger.info("deviceStatus forwarded successfully");
			return "{ \"msg\" : \"deviceStatus forwarded successfully\" }";	
		}else {
			return "{\n\r \"error\" : \"authcode error\"\n}\n";
		}
	}
	
	/*
	 * only for test
	@RequestMapping(value = "/update", method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
	public String updateSensort(@RequestBody DeviceStatus deviceStatus) {

		clientService.sendDeviceStatus(deviceStatus);
		logger.info("deviceStatus sent to server at {}.", new Date());
		return "{ \"msg\" : \"deviceStatus sent to server successfully\" }";
	}
    */

}

