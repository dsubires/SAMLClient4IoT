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

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.representation.Form;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
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


public class ClientHTTPRedirect {

	public static void main(String args[]) {
		NewCookie cookieSimpleSAML = null;
		NewCookie cookieIdpSimpleSAMLAuthToken = null;
		Client client = Client.create();
		String SPURL = "https://sp2.gidlab.rnp.br/test.php";
		// String SPURL = "https://37.48.106.66/test.php";
		String clientId = "";
		String serverId = "";

		try {

			disableValidationSSL();
			long totalTimeS = System.nanoTime();

			// long startTime = System.nanoTime();
			client.setFollowRedirects(Boolean.FALSE);

			/**
			 *
			 * GET SPURL Response 302. Redirect SP -> SP
			 *
			 */
			WebResource webResource = client.resource(SPURL);
			ClientResponse response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE, MediaType.TEXT_XML_TYPE)
					.header("Accept-Encoding", "deflate").get(ClientResponse.class);
			// long endTime = System.nanoTime();

			Iterator<NewCookie> iteratorCookie = response.getCookies().iterator();
			cookieSimpleSAML = new NewCookie("name", "value"); // initialization
			cookieSimpleSAML = (NewCookie) iteratorCookie.next();

			/**
			 *
			 * GET Redirect Response 200: Select id page
			 *
			 */

			webResource = client.resource(response.getLocation());

			response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE)
					.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAML=" + cookieSimpleSAML.getValue())
					.get(ClientResponse.class);
			// endTime = System.nanoTime();

			String urlFinal = urlWithDataForm(response.getEntity(String.class));

			/**
			 *
			 * GET selectIdP.form Response 302: Redirect SP -> SP
			 *
			 */

			webResource = client.resource(urlFinal);
			response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE)
					.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAML=" + cookieSimpleSAML.getValue())
					.get(ClientResponse.class);

			/**
			 *
			 * GET Redirect Response 302: Redirect SP -> IdP
			 *
			 */
			webResource = client.resource(response.getLocation());
			response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE)
					.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAML=" + cookieSimpleSAML.getValue())
					.get(ClientResponse.class);

			/**
			 *
			 * GET Redirect Response 302: Redirect IdP -> IdP
			 *
			 */

			webResource = client.resource(response.getLocation());
			response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE)
					.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAML=" + cookieSimpleSAML.getValue())
					.get(ClientResponse.class);
			iteratorCookie = response.getCookies().iterator();
			cookieSimpleSAML = iteratorCookie.next();

			URI redirectIdPtoIdP = response.getLocation();
			URI endpoint = redirectIdPtoIdP;
			String authState = redirectIdPtoIdP.getQuery();
			authState = authState.substring(10);
			webResource = client.resource(redirectIdPtoIdP);

			/**
			 *
			 * GET Redirect Response 200: Login form
			 *
			 */

			response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE)
					.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAML=" + cookieSimpleSAML.getValue())
					.get(ClientResponse.class);
			// startTime = System.nanoTime();

			webResource = client.resource(endpoint.toString() + "?");
			Form formUser = new Form();
			formUser.add("username", clientId);
			formUser.add("password", "");
			formUser.add("AuthState", authState);

			/**
			 *
			 * POST login.form Response 303: Redirect IdP -> IdP
			 *
			 */
			response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE)
					.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAML=" + cookieSimpleSAML.getValue())
					.post(ClientResponse.class, formUser);
			// endTime = System.nanoTime();
			// System.out
			// .println("POSTing the ClientID and receive an answer. " + ((endTime -
			// startTime) / 1000000) + "ms");

			/**
			 *
			 * GET Redirect Response 200: Login form with Challenge URL
			 *
			 */
			URI redirectAfterChallenge = response.getLocation();
			webResource = client.resource(redirectAfterChallenge);
			response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE)
					.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAML=" + cookieSimpleSAML.getValue())
					.get(ClientResponse.class);
			// endTime = System.nanoTime();
			// System.out.println("Following the redirect and receive an answer with the
			// challenge. ");

			// startTime = System.nanoTime();

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
			challengeList.add(clientId);
			challengeList.add(serverId);
			String[] tempVector = challenge.split(" ");
			for (int i = 0; i < tempVector.length; i++)
				challengeList.add(tempVector[i]);

			Process process = new ProcessBuilder(challengeList).start();
			InputStream is = process.getInputStream();
			InputStreamReader isr = new InputStreamReader(is);
			BufferedReader br = new BufferedReader(isr);
			String line;
			String response_ch = "";

			while ((line = br.readLine()) != null)
				response_ch += line;

			// endTime = System.nanoTime();
			// System.out.println("Calculate the response for the challenge. " + ((endTime -
			// startTime) / 1000000) + "ms");

			/**
			 *
			 * POST login.form Response 302: Redirect IdP -> SP
			 *
			 */
			// startTime = System.nanoTime();
			webResource = client.resource(endpoint.toString());

			// Create form with the user and the challenge response (password)
			Form formUserWithPasswd = new Form();
			formUserWithPasswd.add("username", clientId);
			formUserWithPasswd.add("password", response_ch);
			formUserWithPasswd.add("AuthState", authState);

			response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE)
					.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAML=" + cookieSimpleSAML.getValue())
					.post(ClientResponse.class, formUserWithPasswd);
			// Gets the response from the IDP and converts it to string
			String output = response.getEntity(String.class);

			// endTime = System.nanoTime();
			// System.out.println("POST the response for the challenge and receive the
			// answer with SAMLResponse. "
			// + ((endTime - startTime) / 1000000) + "ms");

			/**
			 * From the IDP response, we get SAMLResponse and the SimpleSAMLAuthToken cookie
			 */
			// startTime = System.nanoTime();
			String str1 = output.substring(output.indexOf("SAMLResponse") + 21, output.length());
			String str2 = str1.substring(0, str1.indexOf("\"")); // str2 == SAMLResponse

			iteratorCookie = response.getCookies().iterator();
			cookieIdpSimpleSAMLAuthToken = new NewCookie("name", "value");
			cookieIdpSimpleSAMLAuthToken = (NewCookie) iteratorCookie.next();
			cookieSimpleSAML = (NewCookie) iteratorCookie.next();

			/**
			 *
			 * POST SP Response 302: Redirect SP -> SP
			 *
			 */

			webResource = client
					.resource("https://sp2.gidlab.rnp.br/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp");
			// .resource("https://37.48.106.66/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp");

			Form form = new Form();
			form.add("SAMLResponse", str2);

			response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE, MediaType.TEXT_XML_TYPE)
					.header("Accept-Encoding", "deflate").header("Referer", endpoint.toString())
					.header("Cookie", "SimpleSAMLAuthToken=" + cookieIdpSimpleSAMLAuthToken.getValue() + ";SimpleSAML="
							+ cookieSimpleSAML.getValue())
					.post(ClientResponse.class, form);

			iteratorCookie = response.getCookies().iterator();

			cookieIdpSimpleSAMLAuthToken = (NewCookie) iteratorCookie.next();
			cookieSimpleSAML = (NewCookie) iteratorCookie.next();

			/**
			 *
			 * GET Redirect Response 200: Finally access to resource
			 *
			 */
			webResource = client.resource(SPURL);

			response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE, MediaType.TEXT_XML_TYPE)
					.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAMLAuthToken="
							+ cookieIdpSimpleSAMLAuthToken.getValue() + ";SimpleSAML=" + cookieSimpleSAML.getValue())
					.get(ClientResponse.class);

			// endTime = System.nanoTime();
			// System.out.println("POST the SAMLResponse and GET resource " + ((endTime -
			// startTime) / 1000000) + "ms");

			System.out.println(response.toString());
			System.out.println(response.getEntity(String.class));
			long totalTimeE = System.nanoTime();
			System.out
					.println("Total time consumed for communication: " + ((totalTimeE - totalTimeS) / 1000000) + "ms");

			System.out.println("successful login \n exiting...");

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Disable validation SSL. It allows access to SP and IDP even if they do not
	 * have certificates signed by a valid entity.
	 */
	private static void disableValidationSSL() throws Exception {
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
		SSLContext sc = SSLContext.getInstance("SSL");
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
	}

	/**
	 * Generate the URL needed to complete the IDP election form.
	 *
	 * @param input
	 *            HTML code of the IDP election page
	 * @return URL as string
	 */
	private static String urlWithDataForm(String input) {
		String[] html = input.split(">");
		String url, entityValue, returnValue, returnID, optionValue;
		url = "";
		entityValue = "";
		returnValue = "";
		returnID = "returnIDParam=idpentityid";
		optionValue = "";
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
				if (html[i].contains("idpiot")) {
					optionValue = html[i].substring(15, html[i].length() - 1);
					optionValue = "idpentityid=" + optionValue;
				}
			}

		}
		return url + "?" + entityValue + "&" + returnValue + "&" + returnID + "&" + optionValue;
	}

}
