package com.dsubires.saml.models;

import javax.ws.rs.core.NewCookie;

/**
 * 
 * Objeto que representa y encapsula la información de un cliente SAML. (POJO)
 * 
 * @author David Subires Parra
 */

public class ClientSAML {

	private String idpHost;
	private String spURL;
	private String clientID;
	private String serverID;
	private String samlResponse;
	private NewCookie simpleSAML;
	private NewCookie simpleSAMLAuthToken;
	private DeviceStatus deviceStatus;
	/**
	 * 
	 * Generalmente, el cliente realiza una única petición de autenticación,
	 * almacenando la cookie recibida para siguientes peticiones. Si el atributo
	 * forceLogin se marca a TRUE, para cada petición de acceso a servicio se
	 * realizará petición de autenticación.
	 * 
	 */
	private boolean forceLogin;
	private boolean insertData;

	public ClientSAML() {
		super();
		setForceLogin(false);
		setInsertData(false);
	}

	public ClientSAML(String idpHost) {
		super();
		setForceLogin(false);
		setInsertData(false);
		setIdpHost(idpHost);
	}

	public String getIdpHost() {
		return idpHost;
	}

	public void setIdpHost(String host) {
		this.idpHost = host;
	}

	public String getSpURL() {
		return spURL;
	}

	public void setSpURL(String spURL) {
		this.spURL = spURL;
	}

	public String getClientID() {
		return clientID;
	}

	public void setClientID(String clientID) {
		this.clientID = clientID;
	}

	public String getServerID() {
		return serverID;
	}

	public void setServerID(String serverID) {
		this.serverID = serverID;
	}

	public NewCookie getSimpleSAML() {
		return simpleSAML;
	}

	public void setSimpleSAML(NewCookie cookie) {
		this.simpleSAML = cookie;
	}

	public NewCookie getSimpleSAMLAuthToken() {
		return simpleSAMLAuthToken;
	}

	public void setSimpleSAMLAuthToken(NewCookie cookie) {
		this.simpleSAMLAuthToken = cookie;
	}

	public String getSamlResponse() {
		return samlResponse;
	}

	public void setSamlResponse(String samlResponse) {
		this.samlResponse = samlResponse;
	}

	public boolean isForceLogin() {
		return forceLogin;
	}

	public void setForceLogin(boolean forceLogin) {
		this.forceLogin = forceLogin;
	}

	public boolean isInsertData() {
		return insertData;
	}

	public void setInsertData(boolean insertData) {
		this.insertData = insertData;
	}

	public DeviceStatus getDeviceStatus() {
		return deviceStatus;
	}

	public void setDeviceStatus(DeviceStatus deviceStatus) {
		this.deviceStatus = deviceStatus;
	}

	@Override
	public String toString() {
		return "ClientHTTPRedirect [host=" + idpHost + ", spURL=" + spURL + ", clientID=" + clientID + ", serverID="
				+ serverID + ", samlResponse=" + samlResponse + ", simpleSAML=" + simpleSAML + ", simpleSAMLAuthToken="
				+ simpleSAMLAuthToken + ", forceLogin=" + forceLogin + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((clientID == null) ? 0 : clientID.hashCode());
		result = prime * result + ((idpHost == null) ? 0 : idpHost.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ClientSAML other = (ClientSAML) obj;
		if (clientID == null) {
			if (other.clientID != null)
				return false;
		} else if (!clientID.equals(other.clientID))
			return false;
		if (idpHost == null) {
			if (other.idpHost != null)
				return false;
		} else if (!idpHost.equals(other.idpHost))
			return false;
		return true;
	}

}
