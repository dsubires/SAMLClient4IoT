package com.dsubires.saml.services;

import java.util.Date;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.dsubires.saml.models.ClientHTTPRedirect;
import com.dsubires.saml.models.DeviceStatus;

@Service
public class ClientService {
	
	@Value("${idp.host}")
	private String idpHost;
	@Value("${idp.client.id}")
	private String clientID;
	@Value("${idp.server.id}")
	private String serverID;
	@Value("${idp.test.file}")
	private String testFile;
	private Logger logger = LogManager.getLogger("ClientService");
	private ClientHTTPRedirect client = new ClientHTTPRedirect();
	

	
	
	public String authentication() {
		
		logger.info("sending authentication at {}", new Date());
		// login (saml for devices)
		client.setIdpHost(idpHost);
		client.setClientID(clientID);
		client.setServerID(serverID);
		client.setForceLogin(true);
		client.setInsertData(false);
		client.setSpURL("https://" + client.getIdpHost() + "/" + testFile);
				
		return client.accessToSP();
		
	}
	
	public void authenticationFail() {
		
		logger.info("sending FAKE authentication at {}", new Date());
		client.sendFakeAuthentication();
		
	}
	
	public String sendDeviceStatus(DeviceStatus deviceStatus) {
		
		logger.info("sending deviceStatus", new Date());
		// login (saml for devices)
		client.setIdpHost(idpHost);
		client.setClientID(clientID);
		client.setServerID(serverID);
		client.setForceLogin(false);
		client.setInsertData(true);
		client.setDeviceStatus(deviceStatus);
		client.setSpURL("https://" + client.getIdpHost() + "/" + testFile);
				
		return client.accessToSP();
		
	}
	
	public String sendDeviceStatusMesh(String meshHost, DeviceStatus deviceStatus) {
		
		logger.info("sending mesh to {} at {}", meshHost, new Date());		
		return client.sendMesh(meshHost, deviceStatus);
		
	}

}
