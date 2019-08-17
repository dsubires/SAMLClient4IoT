/**
 * ClientHTTPRedirect
 * 
 * Simple SAML client developed in JAVA. Access an SP, after authentication on
 * an IdP through HTTP REDIRECT BIND (without SAML library) using a special authentication source for
 * devices (IoT).
 * 
 * @author Subires
 */

package com.dsubires.saml.models;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.representation.Form;

public class ClientHTTPRedirect {

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
	 * Generally the client only makes a single login with the idp and stores the
	 * session cookie. If this attribute, forceLogin, is TRUE, it will always login
	 * with idp.
	 * 
	 */
	private boolean forceLogin;
	private boolean insertData;
	//
	private Client client = Client.create();
	private ClientResponse response;
	private WebResource webResource;
	private URI endpoint;

	private String testFile = "test.php";
	private String elasticFile = "sensorupdateELK.php";
	private String deviceAuthClientPath = "/home/ctgid/deviceauthentication/client";

	private Iterator<NewCookie> iteratorCookie;

	private Logger logger = LogManager.getLogger("saml-client");

	public ClientHTTPRedirect() {
		super();
		setForceLogin(false);
		setInsertData(false);
	}

	public ClientHTTPRedirect(String idpHost) {
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

	public NewCookie getSimpleSAMLAuthToken() {
		return simpleSAMLAuthToken;
	}

	public String getSamlResponse() {
		return samlResponse;
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
		ClientHTTPRedirect other = (ClientHTTPRedirect) obj;
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

	/**
	 * Disable validation SSL. It allows access to SP and IDP even if they do not
	 * have certificates signed by a valid entity.
	 */
	private void disableValidationSSL() {
		// Create a trust manager that does not validate certificate chains
		TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
			public java.security.cert.X509Certificate[] getAcceptedIssuers() {
				return null;
			}

			public void checkClientTrusted(X509Certificate[] certs, String authType) {
			}

			public void checkServerTrusted(X509Certificate[] certs, String authType) {
			}
		} };

		// Install the all-trusting trust manager
		SSLContext sc;
		try {
			sc = SSLContext.getInstance("SSL");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

			// Create all-trusting host name verifier
			HostnameVerifier allHostsValid = new HostnameVerifier() {
				public boolean verify(String hostname, SSLSession session) {
					return true;
				}
			};

			// Install the all-trusting host verifier
			HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (KeyManagementException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Generate the URL needed to complete the IDP selection form.
	 *
	 * @param input HTML code of the IDP election page
	 * @return URL as string
	 */
	private String urlWithDataForm(String input) {
		String[] html = input.split(">");
		String url, entityValue, returnValue, returnID, optionValue;
		url = "";
		entityValue = "";
		returnValue = "";
		optionValue = "";
		returnID = "returnIDParam=idpentityid";
		for (int i = 0; i < html.length; i++) {
			if (html[i].contains("action")) {
				url = html[i].substring(32, html[i].length() - 1);
			} else if (html[i].contains("name=\"entityID\"")) {
				entityValue = html[i].substring(53, html[i].length() - 2);
				entityValue = "entityID=" + entityValue;
			} else if (html[i].contains("\"return\" value")) {
				returnValue = html[i].substring(51, html[i].length() - 2);
				returnValue = "return=" + returnValue;
			} else if (html[i].contains("<option value=")) {
				if (html[i].contains(idpHost)) {
					optionValue = "idpentityid=https://" + idpHost + "/simplesaml/saml2/idp/metadata.php";

				}
			}

		}

		return url + "?" + entityValue + "&" + returnValue + "&" + returnID + "&" + optionValue;
	}

	private boolean login() {

		disableValidationSSL();
		client.setFollowRedirects(Boolean.FALSE);

		/**
		 *
		 * GET SPURL Response 302. Redirect SP -> SP
		 *
		 */
		webResource = client.resource(spURL);
		response = webResource.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
				MediaType.TEXT_HTML_TYPE, MediaType.TEXT_XML_TYPE).header("Accept-Encoding", "deflate")
				.get(ClientResponse.class);

		Iterator<NewCookie> iteratorCookie = response.getCookies().iterator();
		while (iteratorCookie.hasNext()) {
			NewCookie cookie = iteratorCookie.next();
			if (cookie.getName().equals("SimpleSAMLAuthToken")) {
				simpleSAMLAuthToken = cookie;
			} else if (cookie.getName().equals("SimpleSAML")) {
				simpleSAML = cookie;
			}
		}

		/**
		 *
		 * GET Redirect Response 200: Select id page
		 *
		 */

		webResource = client.resource(response.getLocation());

		response = webResource
				.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE, MediaType.TEXT_HTML_TYPE)
				.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAML=" + simpleSAML.getValue())
				.get(ClientResponse.class);

		String urlFinal = urlWithDataForm(response.getEntity(String.class));

		/**
		 *
		 * GET selectIdP.form Response 302: Redirect SP -> SP
		 *
		 */

		webResource = client.resource(urlFinal);
		response = webResource
				.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE, MediaType.TEXT_HTML_TYPE)
				.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAML=" + simpleSAML.getValue())
				.get(ClientResponse.class);

		/**
		 *
		 * GET Redirect Response 302: Redirect SP -> IdP
		 *
		 */
		webResource = client.resource(response.getLocation());
		response = webResource
				.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE, MediaType.TEXT_HTML_TYPE)
				.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAML=" + simpleSAML.getValue())
				.get(ClientResponse.class);

		/**
		 *
		 * GET Redirect Response 302: Redirect IdP -> IdP
		 *
		 */

		webResource = client.resource(response.getLocation());
		response = webResource
				.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE, MediaType.TEXT_HTML_TYPE)
				.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAML=" + simpleSAML.getValue())
				.get(ClientResponse.class);
		iteratorCookie = response.getCookies().iterator();
		while (iteratorCookie.hasNext()) {
			NewCookie cookie = iteratorCookie.next();
			if (cookie.getName().equals("SimpleSAMLAuthToken")) {
				simpleSAMLAuthToken = cookie;
			} else if (cookie.getName().equals("SimpleSAML")) {
				simpleSAML = cookie;
			}
		}

		URI redirectIdPtoIdP = response.getLocation();
		endpoint = redirectIdPtoIdP;
		String authState = redirectIdPtoIdP.getQuery();
		authState = authState.substring(10);
		webResource = client.resource(redirectIdPtoIdP);

		/**
		 *
		 * GET Redirect Response 200: Login form
		 *
		 */

		response = webResource
				.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE, MediaType.TEXT_HTML_TYPE)
				.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAML=" + simpleSAML.getValue())
				.get(ClientResponse.class);

		webResource = client.resource(endpoint.toString());
		Form formUser = new Form();
		formUser.add("username", clientID);
		formUser.add("password", "");
		formUser.add("AuthState", authState);

		/**
		 *
		 * POST login.form Response 303: Redirect IdP -> IdP
		 *
		 */
		response = webResource
				.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE, MediaType.TEXT_HTML_TYPE)
				.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAML=" + simpleSAML.getValue())
				.post(ClientResponse.class, formUser);

		/**
		 *
		 * GET Redirect Response 200: Login form with Challenge URL
		 *
		 */
		URI redirectAfterChallenge = response.getLocation();
		webResource = client.resource(redirectAfterChallenge);
		response = webResource
				.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE, MediaType.TEXT_HTML_TYPE)
				.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAML=" + simpleSAML.getValue())
				.get(ClientResponse.class);

		// look for challenge in URL
		String challenge = redirectAfterChallenge.getQuery();
		int foundChallenge = challenge.indexOf("challengeEncrypted");
		if (foundChallenge != -1)
			challenge = challenge.substring(foundChallenge + 19, challenge.length());
		challenge = challenge.replace('|', ' ');

		// Run the application in C to get the encrypted response
		List<String> challengeList = new ArrayList<String>();
		challengeList.add(deviceAuthClientPath);
		challengeList.add("1");
		challengeList.add(clientID);
		challengeList.add(serverID);
		String[] tempVector = challenge.split(" ");
		for (int i = 0; i < tempVector.length; i++)
			challengeList.add(tempVector[i]);

		Process process;

		try {

			process = new ProcessBuilder(challengeList).start();
			InputStream is = process.getInputStream();
			InputStreamReader isr = new InputStreamReader(is);
			BufferedReader br = new BufferedReader(isr);
			String line;
			String response_ch = "";

			while ((line = br.readLine()) != null)
				response_ch += line;

			/**
			 *
			 * POST login.form Response 302: Redirect IdP -> SP
			 *
			 */
			// startTime = System.nanoTime();
			webResource = client.resource(endpoint.toString());

			// Create form with the user and the challenge response (password)
			Form formUserWithPasswd = new Form();
			formUserWithPasswd.add("username", clientID);
			formUserWithPasswd.add("password", response_ch);
			formUserWithPasswd.add("AuthState", authState);

			response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE)
					.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAML=" + simpleSAML.getValue())
					.post(ClientResponse.class, formUserWithPasswd);

			// Gets the response from the IDP and converts it to string
			String output = response.getEntity(String.class);

			/**
			 * From the IDP response, we get SAMLResponse and the SimpleSAMLAuthToken cookie
			 */
			// startTime = System.nanoTime();
			String str1 = output.substring(output.indexOf("SAMLResponse") + 21, output.length());
			String str2 = str1.substring(0, str1.indexOf("\"")); // str2 == SAMLResponse

			iteratorCookie = response.getCookies().iterator();
			while (iteratorCookie.hasNext()) {
				NewCookie cookie = iteratorCookie.next();
				if (cookie.getName().equals("SimpleSAMLAuthToken")) {
					simpleSAMLAuthToken = cookie;
				} else if (cookie.getName().equals("SimpleSAML")) {
					simpleSAML = cookie;
				}
			}

			samlResponse = str2;

			if (str2.equals("")) {
				return false;
			}
			return true;

		} catch (IOException e) {
			e.printStackTrace();
		}
		return false;
	}

	private String accessWebResource() {

		/**
		 *
		 * POST SP Response 302: Redirect SP -> SP
		 *
		 */

		webResource = client.resource("https://" + idpHost + "/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp");

		Form form = new Form();
		form.add("SAMLResponse", samlResponse);

		response = webResource
				.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE, MediaType.TEXT_HTML_TYPE,
						MediaType.TEXT_XML_TYPE)
				.header("Accept-Encoding", "deflate").header("Referer", endpoint.toString())
				.header("Cookie", "SimpleSAMLAuthToken=" + simpleSAMLAuthToken.getValue() + ";SimpleSAML="
						+ simpleSAML.getValue())
				.post(ClientResponse.class, form);

		iteratorCookie = response.getCookies().iterator();

		while (iteratorCookie.hasNext()) {
			NewCookie cookie = iteratorCookie.next();
			if (cookie.getName().equals("SimpleSAMLAuthToken")) {
				simpleSAMLAuthToken = cookie;
			} else if (cookie.getName().equals("SimpleSAML")) {
				simpleSAML = cookie;
			}
		}

		if (!insertData) {

			/**
			 *
			 * GET Redirect Response 200: Finally access to resource
			 *
			 */
			webResource = client.resource(spURL);

			response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE, MediaType.TEXT_XML_TYPE)
					.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAMLAuthToken="
							+ simpleSAMLAuthToken.getValue() + ";SimpleSAML=" + simpleSAML.getValue())
					.get(ClientResponse.class);

			// endTime = System.nanoTime();
			// System.out.println("POST the SAMLResponse and GET resource " + ((endTime -
			// startTime) / 1000000) + "ms");

			// System.out.println(response.toString());
			// System.out.println(response.getEntity(String.class));
			return response.getEntity(String.class);

		} else {
			if (deviceStatus == null) {
				return "Error: deviceStatus no seteado";
			}

			webResource = client.resource(spURL.replace(testFile, elasticFile));

			Form formDevice = new Form();
			formDevice.add("sensor", deviceStatus.getDevice());
			formDevice.add("data", deviceStatus.getTemperature());

			response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE, MediaType.TEXT_XML_TYPE)
					.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAMLAuthToken="
							+ simpleSAMLAuthToken.getValue() + ";SimpleSAML=" + simpleSAML.getValue())
					.post(ClientResponse.class, formDevice);

			return response.getEntity(String.class);
		}

	}

	public String accessToSP() {

		long start = System.nanoTime();

		if (samlResponse == null || samlResponse.equals("") || forceLogin) {
			login();
		}

		if (samlResponse == null || samlResponse.equals("")) {
			return "Error login";
		} else {
			String html = accessWebResource();
			long end = System.nanoTime();
			logger.info("{} ms", (end - start) / 1000000);
			return html;
		}
	}

	public String sendMesh(String hostMesh, DeviceStatus deviceStatus) {

		webResource = client.resource("http://" + hostMesh + ":8080/mesh/forward");
		String json = "{\r\n" + "	\"authcode\" : \"KLG7efiDbedjzwrZ\",\r\n" + "	\"deviceStatus\" : {\r\n"
				+ "  	  \"device\" : \"" + deviceStatus.getDevice() + "\",\r\n" + "	  \"temperature\" : "
				+ deviceStatus.getTemperature() + "\r\n" + "    }\r\n" + "}";
		response = webResource.type(MediaType.APPLICATION_JSON).post(ClientResponse.class, json);

		return response.getEntity(String.class);
	}

	public void sendFakeAuthentication() {

		
		
		client.setFollowRedirects(Boolean.FALSE);

		/**
		 *
		 * GET SPURL Response 302. Redirect SP -> SP
		 *
		 */
		webResource = client.resource("http://192.168.1.168/simplesaml/module.php/core/authenticate.php?as=admin");
		response = webResource.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
				MediaType.TEXT_HTML_TYPE, MediaType.TEXT_XML_TYPE).header("Accept-Encoding", "deflate")
				.get(ClientResponse.class);
		
		
		iteratorCookie = response.getCookies().iterator();
		while (iteratorCookie.hasNext()) {
			NewCookie cookie = iteratorCookie.next();
			if (cookie.getName().equals("SimpleSAMLAuthToken")) {
				simpleSAMLAuthToken = cookie;
			} else if (cookie.getName().equals("SimpleSAML")) {
				simpleSAML = cookie;
			}
		}
		
		URI redirectIdPtoIdP = response.getLocation();
		endpoint = redirectIdPtoIdP;
		String authState = redirectIdPtoIdP.getQuery();
		authState = authState.substring(10);
		webResource = client.resource(redirectIdPtoIdP);
		

		response = webResource
				.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE, MediaType.TEXT_HTML_TYPE)
				.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAML=" + simpleSAML.getValue())
				.get(ClientResponse.class);
		
		iteratorCookie = response.getCookies().iterator();
		while (iteratorCookie.hasNext()) {
			NewCookie cookie = iteratorCookie.next();
			if (cookie.getName().equals("SimpleSAMLAuthToken")) {
				simpleSAMLAuthToken = cookie;
			} else if (cookie.getName().equals("SimpleSAML")) {
				simpleSAML = cookie;
			}
		}

		

		webResource = client.resource(endpoint.toString());
		Form formUser = new Form();
		formUser.add("password", "fakepassword");
		formUser.add("AuthState", authState);

		/**
		 *
		 * POST login.form Response 303: Redirect IdP -> IdP
		 *
		 */
		response = webResource
				.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE, MediaType.TEXT_HTML_TYPE)
				.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAML=" + simpleSAML.getValue())
				.post(ClientResponse.class, formUser);
		
	}

}
