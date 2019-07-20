/**

 * ClientHTTPRedirect

 * 

 * Simple SAML client developed in JAVA. Access an SP, after authentication on

 * an IdP through HTTP REDIRECT BIND (without SAML library) using a special authentication source for

 * devices (IoT).

 * 

 * @author Subires

 */



package com.dsubires.saml;



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



import com.sun.jersey.api.client.Client;

import com.sun.jersey.api.client.ClientResponse;

import com.sun.jersey.api.client.WebResource;

import com.sun.jersey.api.representation.Form;



public class ClientHTTPRedirect {



	private String host;

	private String spURL;

	private String clientID;

	private String serverID;

	private String samlResponse;

	private NewCookie simpleSAML;

	private NewCookie simpleSAMLAuthToken;

	/**

	 * 

	 * Generally the client only makes a single login with the idp and stores the

	 * session cookie. If this attribute, forceLogin, is TRUE, it will always login with idp.

	 * 

	 */

	private boolean forceLogin;

	//

	private Client client = Client.create();

	private ClientResponse response;

	private WebResource webResource;

	private URI endpoint;



	private Iterator<NewCookie> iteratorCookie;



	public ClientHTTPRedirect() {

		super();

		setForceLogin(false);

	}



	public String getHost() {

		return host;

	}



	public void setHost(String host) {

		this.host = host;

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



	@Override

	public String toString() {

		return "ClientHTTPRedirect [host=" + host + ", spURL=" + spURL + ", clientID=" + clientID + ", serverID="

				+ serverID + ", samlResponse=" + samlResponse + ", simpleSAML=" + simpleSAML + ", simpleSAMLAuthToken="

				+ simpleSAMLAuthToken + ", forceLogin=" + forceLogin + "]";

	}



	@Override

	public int hashCode() {

		final int prime = 31;

		int result = 1;

		result = prime * result + ((clientID == null) ? 0 : clientID.hashCode());

		result = prime * result + ((host == null) ? 0 : host.hashCode());

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

		if (host == null) {

			if (other.host != null)

				return false;

		} else if (!host.equals(other.host))

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

				if (html[i].contains(host)) {

					optionValue = "idpentityid=https://" + host + "/simplesaml/saml2/idp/metadata.php";



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

		simpleSAML = (NewCookie) iteratorCookie.next();



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

		simpleSAML = iteratorCookie.next();



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

		challengeList.add("/home/ctgid/deviceauthentication/client");

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

			simpleSAMLAuthToken = (NewCookie) iteratorCookie.next();

			simpleSAML = (NewCookie) iteratorCookie.next();



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



	private String getData() {



		/**

		 *

		 * POST SP Response 302: Redirect SP -> SP

		 *

		 */



		webResource = client.resource("https://" + host + "/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp");



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



		/**

		 *

		 * GET Redirect Response 200: Finally access to resource

		 *

		 */

		webResource = client.resource(spURL);



		response = webResource

				.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE, MediaType.TEXT_HTML_TYPE,

						MediaType.TEXT_XML_TYPE)

				.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAMLAuthToken="

						+ simpleSAMLAuthToken.getValue() + ";SimpleSAML=" + simpleSAML.getValue())

				.get(ClientResponse.class);



		// endTime = System.nanoTime();

		// System.out.println("POST the SAMLResponse and GET resource " + ((endTime -

		// startTime) / 1000000) + "ms");



		System.out.println(response.toString());

//		System.out.println(response.getEntity(String.class));



		return response.getEntity(String.class);

	}



	public String getResource() {

		long start = System.nanoTime();

		if (samlResponse == null || samlResponse.equals("") || forceLogin) {

			login();

		}

		if (samlResponse == null || samlResponse.equals("")) {

			return "Error login";

		} else {

			String html = getData();

			long end = System.nanoTime();

			System.out.println((end - start) / 1000000 + " ms");

			return html;

		}

	}

}

