package com.dsubires.saml;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;
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

import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;
import org.opensaml.xml.util.Base64;


/**
 * ClientPOST
 * 
 * Simple SAML client developed in JAVA. Access an SP, after authentication on an 
 * IdP through POST BIND (with SAML library) using a special authentication source for devices (IoT)
 * 
 * @author Subires
 */
public class ClientPOST {


	public static void main(String args[]) throws InterruptedException {

		long startTimeTT = System.nanoTime();

		SAMLUtils saml = null;
		NewCookie cookieSimpleSAML = null;
		NewCookie cookieIdpSimpleSAMLAuthToken = null;
		ClientConfig config = new DefaultClientConfig();
		Client client = Client.create(config);
		String SPURL = "https://37.48.106.66/test.php";
		// String SPURL = "https://sp2.gidlab.rnp.br/test.php";
		String clientId = "Baria";
		String serverId = "Alice";

		try {

			disableValidationSSL();

			/**
			 * 
			 * Create SAMLAuthnRequest and code it in base 64
			 * 
			 */
			
			saml = new SAMLUtils();
			saml.bootstrap();
			long startTimeT = System.nanoTime();
			AuthnRequest authnRequest = saml.createAuthnRequest();
			Element authnRequestXML = saml.authnRequestToXML(authnRequest);
			String authnRequestXMLstr = XMLHelper.nodeToString(authnRequestXML);
			byte[] input = authnRequestXMLstr.getBytes("UTF-8");
			String bytes = Base64.encodeBytes(input);

			/**
			 * 
			 * POST IDP-SSOService -> 303
			 * 
			 */
			client.setFollowRedirects(Boolean.FALSE);

			WebResource webResource = client
					.resource("https://idpiot.cafeexpresso.rnp.br/simplesaml/saml2/idp/SSOService.php");

			Form form = new Form();
			form.add("SAMLRequest", bytes);

			ClientResponse response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE, MediaType.TEXT_XML_TYPE)
					.header("Accept-Encoding", "deflate").post(ClientResponse.class, form);

			Iterator<NewCookie> iteratorCookie = response.getCookies().iterator();
			cookieSimpleSAML = new NewCookie("name", "value"); 
			cookieSimpleSAML = (NewCookie) iteratorCookie.next();

			/**
			 * GET IDP-logindevicepass -> 200
			 */
			URI redirectIdPtoIdP = response.getLocation();
			URI endpoint = redirectIdPtoIdP;
			String authState = redirectIdPtoIdP.getQuery();

			webResource = client.resource(endpoint);
			response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE)
					.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAML=" + cookieSimpleSAML.getValue())
					.get(ClientResponse.class);

			/**
			 * 
			 * POST IDP-logindevicepass -> 303 
			 * POST with a blank password to generate the challenge
			 * 
			 */

			authState = authState.substring(10);
			webResource = client.resource(endpoint.toString() + "?");

			Form formUser = new Form();
			formUser.add("username", clientId);
			formUser.add("password", "");
			formUser.add("AuthState", authState);

			response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE)
					.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAML=" + cookieSimpleSAML.getValue())
					.post(ClientResponse.class, formUser);

			/**
			 * 
			 * GET IDP-logindevicepass -> 200 
			 * Get to the last redirect to access the login form with the challenge in the URL
			 * 
			 */
			URI redirectAfterChallenge = response.getLocation();
			webResource = client.resource(redirectAfterChallenge);


			response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE)
					.header("Accept-Encoding", "deflate")
					.header("Cookie", "SimpleSAML=" + cookieSimpleSAML.getValue()).get(ClientResponse.class);

			// look for the challenge in the URL
			String challenge = redirectAfterChallenge.getQuery();
			int foundChallenge = challenge.indexOf("challengeEncrypted");
			if (foundChallenge != -1)
				challenge = challenge.substring(foundChallenge + 19, challenge.length() - 1);


			challenge = challenge.replace('|', ' ');

			// Run the application in C to obtain the encrypted response of the challenge
			List<String> challengeList = new ArrayList<String>();
			challengeList.add("/home/ctgid/deviceauthentication/client");
			challengeList.add("1");
			challengeList.add(clientId);
			challengeList.add(serverId);
			String[] tempVector = challenge.split(" ");
			for (int i = 0; i < tempVector.length; i++) {
				challengeList.add(tempVector[i]);
			}

			Process process = new ProcessBuilder(challengeList).start();
			InputStream is = process.getInputStream();
			InputStreamReader isr = new InputStreamReader(is);
			BufferedReader br = new BufferedReader(isr);
			String line;
			String response_ch = "";

			while ((line = br.readLine()) != null)
				response_ch += line;

			/**
			 * 
			 * POST IDP-logindevicepass -> 200 
			 * POST with user, password (challenge response) and AuthState 
			 *  
			 */
			webResource = client.resource(endpoint.toString());

			Form formUserWithPasswd = new Form();
			formUserWithPasswd.add("username", clientId);
			formUserWithPasswd.add("password", response_ch);
			formUserWithPasswd.add("AuthState", authState);


			response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE)
					.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAML=" + cookieSimpleSAML.getValue())
					.post(ClientResponse.class, formUserWithPasswd);


			/**
			 * 
			 * From the IDP response we obtain the SAMLResponse and the appropriate Cookie
			 * 
			 */
			
			String output = response.getEntity(String.class);
			String str1 = output.substring(output.indexOf("SAMLResponse") + 21, output.length());
			String str2 = str1.substring(0, str1.indexOf("\"")); // str2 == SAMLResponse

			// byte[] responseBytes = Base64.decode(str2);
			// String responseStr = new String(responseBytes, "UTF-8");
			// SAMLResponse.Base64.decode()

			iteratorCookie = response.getCookies().iterator();
			cookieIdpSimpleSAMLAuthToken = new NewCookie("name", "value");

			cookieIdpSimpleSAMLAuthToken = (NewCookie) iteratorCookie.next();
			cookieSimpleSAML = (NewCookie) iteratorCookie.next();

			/**
			 * 
			 * POST SP-saml2-acs -> 303  
			 * Send the SAMLResponse that the IDP has given us to the SP to be able to access the resource
			 *  
			 */

			webResource = client
					.resource("https://37.48.106.66/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp");

			form = new Form();
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
			 * GET SP-resource (SPURL) -> 200  
			 * Finaly access to SP resource
			 *  
			 */

			webResource = client.resource(SPURL);

			response = webResource
					.accept(MediaType.APPLICATION_XHTML_XML_TYPE, MediaType.APPLICATION_XML_TYPE,
							MediaType.TEXT_HTML_TYPE, MediaType.TEXT_XML_TYPE)
					.header("Accept-Encoding", "deflate").header("Cookie", "SimpleSAMLAuthToken="
							+ cookieIdpSimpleSAMLAuthToken.getValue() + ";SimpleSAML=" + cookieSimpleSAML.getValue())
					.get(ClientResponse.class);
			System.out.println(response);
			System.out.println(response.getEntity(String.class));

			long endTimeT = System.nanoTime();
			System.out.println("Total time consumed for communication: " + ((endTimeT - startTimeT) / 1000000) + "ms");

			System.out.println("Total time consumed for communication (with library load time): "
					+ ((endTimeT - startTimeTT) / 1000000) + "ms");

			System.out.println("successful login \n exiting...");

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Disable validation SSL. It allows access to SP and IDP even if they do not
	 * have certificates signed by a valid entity.
	 *
	 * @throws Exception the exception
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

}
