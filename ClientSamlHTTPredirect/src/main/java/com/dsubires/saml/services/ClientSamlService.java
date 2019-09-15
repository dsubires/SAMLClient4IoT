package com.dsubires.saml.services;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.dsubires.saml.models.ClientSAML;
import com.dsubires.saml.models.DeviceStatus;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.representation.Form;

/**
 * 
 * * Cliente SAML (simpleSAMLphp). Capa de servicio que ofrece funcionalidad
 * para acceder a servicios web alojados en el proveedor de servicio,
 * posibilitando el envío de información al servidor, y para realizar la
 * autenticación adaptada a dispositivos mediante el proveedor de identidad.
 * Implementa el binding HTTP Redirect.
 * 
 * 
 * @author David Subires Parra
 *
 */

@Service
public class ClientSamlService {

	@Value("${idp.host}")
	private String idpHost;
	@Value("${idp.client.id}")
	private String clientID;
	@Value("${idp.server.id}")
	private String serverID;
	@Value("${sp.test.file}")
	private String testFile;
	@Value("${sp.elastic.insert.file}")
	String elasticFile;
	@Value("${device.auth.path}")
	private String deviceAuthClientPath;

	private Logger logger = LogManager.getLogger("ClientService");
	private ClientSAML clientSAML = new ClientSAML();
	private Client clientJersey = Client.create();
	private ClientResponse response;
	private WebResource webResource;
	private URI endpoint;
	private Iterator<NewCookie> iteratorCookie;

	/**
	 * Método que realiza la autenticación con el proveedor de identidad. Para
	 * comprobar que se ha realizado correctamente, accede al servicio test.php y
	 * devuelve el resultado.
	 * 
	 * @return devuelve el resultado de acceder al servicio test.php tras la
	 *         autenticación
	 */
	public String authentication() {

		logger.info("sending authentication at {}", new Date());
		String spURL = "https://" + idpHost + "/" + testFile;
		// login (saml for devices)
		clientSAML.setIdpHost(idpHost);
		clientSAML.setClientID(clientID);
		clientSAML.setServerID(serverID);
		clientSAML.setForceLogin(true);
		clientSAML.setInsertData(false);
		clientSAML.setSpURL(spURL);
		return accessToSP();

	}

	/**
	 * Método que realiza un intento fallido de autenticación empleando el usuario
	 * 'admin'
	 */
	public void authenticationFail() {

		logger.info("sending FAKE authentication at {}", new Date());
		sendFakeAuthentication();

	}

	/**
	 * Método que envía la información capturada por los sensores al servicio web
	 * que integra la conexión a Elasticsearch.
	 * 
	 * @param deviceStatus información que se desea enviar a Elastic
	 * @return devuelve la respuesta de Elasticsearch tras la indexación
	 */
	public String sendDeviceStatus(DeviceStatus deviceStatus) {

		String spURL = "https://" + idpHost + "/" + testFile;

		logger.info("sending deviceStatus at {}", new Date());
		// login (saml for devices)
		clientSAML.setIdpHost(idpHost);
		clientSAML.setClientID(clientID);
		clientSAML.setServerID(serverID);
		clientSAML.setForceLogin(false);
		clientSAML.setInsertData(true);
		clientSAML.setDeviceStatus(deviceStatus);
		clientSAML.setSpURL(spURL);

		return accessToSP();

	}

	/**
	 * Método que implementa el envío de la petición mesh al servicio web REST de
	 * otro dispositivo.
	 * 
	 * @param meshHost     dirección del dispositivo al que se enviará la petición
	 *                     mesh
	 * @param deviceStatus información que se desea enviar al servidor
	 * @return devuelve la respuesta generada por el servicio web REST del otro
	 *         dispositivo.
	 */
	public String sendDeviceStatusMesh(String meshHost, DeviceStatus deviceStatus) {

		logger.info("sending mesh to {} at {}", meshHost, new Date());

		webResource = clientJersey.resource("http://" + meshHost + ":8080/mesh/forward");
		String json = "{\r\n" + "	\"authcode\" : \"KLG7efiDbedjzwrZ\",\r\n" + "	\"deviceStatus\" : {\r\n"
				+ "  	  \"device\" : \"" + deviceStatus.getDevice() + "\",\r\n" + "	  \"temperature\" : "
				+ deviceStatus.getTemperature() + "\r\n" + "    }\r\n" + "}";
		response = webResource.type(MediaType.APPLICATION_JSON).post(ClientResponse.class, json);

		return response.getEntity(String.class);

	}

	/**
	 * Deshabilita las validaciones SSL. Permite el acceso al SP e IdP incluso si
	 * estos no cuentan con un certificado firmado por una entidad válida.
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
	 * Método que realiza la autenticación adaptada a dispositivos para
	 * identificarse en el proveedor de identidad (IdP)
	 * 
	 * @return devuelve true o false en función de si la autenticación se ha
	 *         realizado con éxito o no.
	 */
	private boolean login() {

		disableValidationSSL();
		clientJersey.setFollowRedirects(Boolean.FALSE);

		/**
		 *
		 * GET SPURL Response 302. Redirect SP -> SP
		 *
		 */
		webResource = clientJersey.resource(clientSAML.getSpURL());
		response = webResource.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
				MediaType.TEXT_HTML_TYPE, MediaType.TEXT_XML_TYPE).header("Accept-Encoding", "deflate")
				.get(ClientResponse.class);

		Iterator<NewCookie> iteratorCookie = response.getCookies().iterator();
		while (iteratorCookie.hasNext()) {
			NewCookie cookie = iteratorCookie.next();
			if (cookie.getName().equals("SimpleSAMLAuthToken")) {
				clientSAML.setSimpleSAMLAuthToken(cookie);
			} else if (cookie.getName().equals("SimpleSAML")) {
				clientSAML.setSimpleSAML(cookie);
			}
		}

		/**
		 *
		 * GET Redirect Response 200: Select id page
		 *
		 */

		webResource = clientJersey.resource(response.getLocation());

		response = webResource
				.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE, MediaType.TEXT_HTML_TYPE)
				.header("Accept-Encoding", "deflate")
				.header("Cookie", "SimpleSAML=" + clientSAML.getSimpleSAML().getValue()).get(ClientResponse.class);

		String urlFinal = urlWithDataForm(response.getEntity(String.class));

		/**
		 *
		 * GET selectIdP.form Response 302: Redirect SP -> SP
		 *
		 */

		webResource = clientJersey.resource(urlFinal);
		response = webResource
				.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE, MediaType.TEXT_HTML_TYPE)
				.header("Accept-Encoding", "deflate")
				.header("Cookie", "SimpleSAML=" + clientSAML.getSimpleSAML().getValue()).get(ClientResponse.class);

		/**
		 *
		 * GET Redirect Response 302: Redirect SP -> IdP
		 *
		 */
		webResource = clientJersey.resource(response.getLocation());
		response = webResource
				.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE, MediaType.TEXT_HTML_TYPE)
				.header("Accept-Encoding", "deflate")
				.header("Cookie", "SimpleSAML=" + clientSAML.getSimpleSAML().getValue()).get(ClientResponse.class);

		/**
		 *
		 * GET Redirect Response 302: Redirect IdP -> IdP
		 *
		 */

		webResource = clientJersey.resource(response.getLocation());
		response = webResource
				.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE, MediaType.TEXT_HTML_TYPE)
				.header("Accept-Encoding", "deflate")
				.header("Cookie", "SimpleSAML=" + clientSAML.getSimpleSAML().getValue()).get(ClientResponse.class);
		iteratorCookie = response.getCookies().iterator();
		while (iteratorCookie.hasNext()) {
			NewCookie cookie = iteratorCookie.next();
			if (cookie.getName().equals("SimpleSAMLAuthToken")) {
				clientSAML.setSimpleSAMLAuthToken(cookie);
			} else if (cookie.getName().equals("SimpleSAML")) {
				clientSAML.setSimpleSAML(cookie);
			}
		}

		URI redirectIdPtoIdP = response.getLocation();
		endpoint = redirectIdPtoIdP;
		String authState = redirectIdPtoIdP.getQuery();
		authState = authState.substring(10);
		webResource = clientJersey.resource(redirectIdPtoIdP);

		/**
		 *
		 * GET Redirect Response 200: Login form
		 *
		 */

		response = webResource
				.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE, MediaType.TEXT_HTML_TYPE)
				.header("Accept-Encoding", "deflate")
				.header("Cookie", "SimpleSAML=" + clientSAML.getSimpleSAML().getValue()).get(ClientResponse.class);

		webResource = clientJersey.resource(endpoint.toString());
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
				.header("Accept-Encoding", "deflate")
				.header("Cookie", "SimpleSAML=" + clientSAML.getSimpleSAML().getValue())
				.post(ClientResponse.class, formUser);

		/**
		 *
		 * GET Redirect Response 200: Login form with Challenge URL
		 *
		 */
		URI redirectAfterChallenge = response.getLocation();
		webResource = clientJersey.resource(redirectAfterChallenge);
		response = webResource
				.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE, MediaType.TEXT_HTML_TYPE)
				.header("Accept-Encoding", "deflate")
				.header("Cookie", "SimpleSAML=" + clientSAML.getSimpleSAML().getValue()).get(ClientResponse.class);

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
			webResource = clientJersey.resource(endpoint.toString());

			// Create form with the user and the challenge response (password)
			Form formUserWithPasswd = new Form();
			formUserWithPasswd.add("username", clientID);
			formUserWithPasswd.add("password", response_ch);
			formUserWithPasswd.add("AuthState", authState);

			response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE)
					.header("Accept-Encoding", "deflate")
					.header("Cookie", "SimpleSAML=" + clientSAML.getSimpleSAML().getValue())
					.post(ClientResponse.class, formUserWithPasswd);

			// Gets the response from the IDP and converts it to string
			String output = response.getEntity(String.class);

			iteratorCookie = response.getCookies().iterator();
			while (iteratorCookie.hasNext()) {
				NewCookie cookie = iteratorCookie.next();
				if (cookie.getName().equals("SimpleSAMLAuthToken")) {
					clientSAML.setSimpleSAMLAuthToken(cookie);
				} else if (cookie.getName().equals("SimpleSAML")) {
					clientSAML.setSimpleSAML(cookie);
				}
			}

			/**
			 * From the IDP response, we get SAMLResponse and the SimpleSAMLAuthToken cookie
			 */
			// startTime = System.nanoTime();
			String str1 = output.substring(output.indexOf("SAMLResponse") + 21, output.length());
			String str2 = str1.substring(0, str1.indexOf("\"")); // str2 == SAMLResponse

			if (str2.equals("")) {
				return false;
			}

			clientSAML.setSamlResponse(str2);

			return true;

		} catch (IOException e) {
			e.printStackTrace();
		}
		return false;
	}

	/**
	 * Método que, tras la autenticación, accede al servicio web alojado en el
	 * proveedor de servicio.
	 * 
	 * @return devuelve el html generado por el servicio web accedido.
	 */
	private String accessWebResource() {

		/**
		 *
		 * POST SP Response 302: Redirect SP -> SP
		 *
		 */

		webResource = clientJersey
				.resource("https://" + idpHost + "/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp");

		Form form = new Form();
		form.add("SAMLResponse", clientSAML.getSamlResponse());

		response = webResource
				.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE, MediaType.TEXT_HTML_TYPE,
						MediaType.TEXT_XML_TYPE)
				.header("Accept-Encoding", "deflate").header("Referer", endpoint.toString())
				.header("Cookie", "SimpleSAMLAuthToken=" + clientSAML.getSimpleSAMLAuthToken().getValue()
						+ ";SimpleSAML=" + clientSAML.getSimpleSAML().getValue())
				.post(ClientResponse.class, form);

		iteratorCookie = response.getCookies().iterator();

		while (iteratorCookie.hasNext()) {
			NewCookie cookie = iteratorCookie.next();
			if (cookie.getName().equals("SimpleSAMLAuthToken")) {
				clientSAML.setSimpleSAMLAuthToken(cookie);
			} else if (cookie.getName().equals("SimpleSAML")) {
				clientSAML.setSimpleSAML(cookie);
			}
		}

		if (!clientSAML.isInsertData()) {

			/**
			 *
			 * GET Redirect Response 200: Finally access to resource
			 *
			 */
			webResource = clientJersey.resource(clientSAML.getSpURL());

			response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE, MediaType.TEXT_XML_TYPE)
					.header("Accept-Encoding", "deflate")
					.header("Cookie", "SimpleSAMLAuthToken=" + clientSAML.getSimpleSAMLAuthToken().getValue()
							+ ";SimpleSAML=" + clientSAML.getSimpleSAML().getValue())
					.get(ClientResponse.class);

			// endTime = System.nanoTime();
			// System.out.println("POST the SAMLResponse and GET resource " + ((endTime -
			// startTime) / 1000000) + "ms");

			// System.out.println(response.toString());
			// System.out.println(response.getEntity(String.class));
			return response.getEntity(String.class);

		} else {
			DeviceStatus deviceStatus = clientSAML.getDeviceStatus();

			if (deviceStatus == null) {
				return "Error: deviceStatus no seteado";
			}

			webResource = clientJersey.resource(clientSAML.getSpURL().replace(testFile, elasticFile));

			Form formDevice = new Form();
			formDevice.add("sensor", deviceStatus.getDevice());
			formDevice.add("data", deviceStatus.getTemperature());

			response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE, MediaType.TEXT_XML_TYPE)
					.header("Accept-Encoding", "deflate")
					.header("Cookie", "SimpleSAMLAuthToken=" + clientSAML.getSimpleSAMLAuthToken().getValue()
							+ ";SimpleSAML=" + clientSAML.getSimpleSAML().getValue())
					.post(ClientResponse.class, formDevice);

			return response.getEntity(String.class);
		}

	}

	/**
	 * Método general de acceso al SP. Controla que la petición al SP se realiza
	 * tras la autenticación con el IdP.
	 * 
	 * @return devuelve el html generado por el servicio web accedido.
	 */
	private String accessToSP() {

		String samlResponse = clientSAML.getSamlResponse();
		boolean forceLogin = clientSAML.isForceLogin();

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

	/**
	 * Método que implementa la lógica del intento fallido de autenticación enviado
	 * al IdP empleando el usuario 'admin'.
	 */
	public void sendFakeAuthentication() {

		clientJersey.setFollowRedirects(Boolean.FALSE);

		/**
		 *
		 * GET SPURL Response 302. Redirect SP -> SP
		 *
		 */
		webResource = clientJersey
				.resource("http://192.168.1.168/simplesaml/module.php/core/authenticate.php?as=admin");
		response = webResource.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
				MediaType.TEXT_HTML_TYPE, MediaType.TEXT_XML_TYPE).header("Accept-Encoding", "deflate")
				.get(ClientResponse.class);

		iteratorCookie = response.getCookies().iterator();
		while (iteratorCookie.hasNext()) {
			NewCookie cookie = iteratorCookie.next();
			if (cookie.getName().equals("SimpleSAMLAuthToken")) {
				clientSAML.setSimpleSAMLAuthToken(cookie);
			} else if (cookie.getName().equals("SimpleSAML")) {
				clientSAML.setSimpleSAML(cookie);
			}
		}

		URI redirectIdPtoIdP = response.getLocation();
		endpoint = redirectIdPtoIdP;
		String authState = redirectIdPtoIdP.getQuery();
		authState = authState.substring(10);
		webResource = clientJersey.resource(redirectIdPtoIdP);

		response = webResource
				.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE, MediaType.TEXT_HTML_TYPE)
				.header("Accept-Encoding", "deflate")
				.header("Cookie", "SimpleSAML=" + clientSAML.getSimpleSAML().getValue()).get(ClientResponse.class);

		iteratorCookie = response.getCookies().iterator();
		while (iteratorCookie.hasNext()) {
			NewCookie cookie = iteratorCookie.next();
			if (cookie.getName().equals("SimpleSAMLAuthToken")) {
				clientSAML.setSimpleSAMLAuthToken(cookie);
			} else if (cookie.getName().equals("SimpleSAML")) {
				clientSAML.setSimpleSAML(cookie);
			}
		}

		webResource = clientJersey.resource(endpoint.toString());
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
				.header("Accept-Encoding", "deflate")
				.header("Cookie", "SimpleSAML=" + clientSAML.getSimpleSAML().getValue())
				.post(ClientResponse.class, formUser);

	}

	/**
	 * Genera la URL necesaria para completar el formulario de selección de IdP
	 *
	 * @param input código HTML de la página de selección de IdP
	 * @return devuelve la URL como cadena de texto
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

}
