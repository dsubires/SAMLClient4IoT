package com.dsubires.saml;

import java.security.NoSuchAlgorithmException;
import javax.xml.namespace.QName;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.impl.AuthnRequestMarshaller;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.MarshallingException;
import org.w3c.dom.Element;

/**
 * SAMLUtils class. It allows to perform three actions: Initialize the SAML
 * library, create an authnRequest and transform it into XML. In addition, to
 * support these functions, it has a private method
 *
 * @author Subires
 */
public class SAMLUtils {

	/**
	 * Initializes the OpenSAML library, loading default configurations.
	 */
	public void bootstrap() {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException ex) {
			ex.printStackTrace();
		}
	}

	/**
	 * Create AuthnRequest that will be sent to the IDP (destination), in order to
	 * access a resource offered within our SP (issuer)
	 *
	 * @return the authn request
	 */
	public AuthnRequest createAuthnRequest() {

		AuthnRequest authnRequest = this.create(AuthnRequest.class, AuthnRequest.DEFAULT_ELEMENT_NAME);

		try {
			SecureRandomIdentifierGenerator generator = new SecureRandomIdentifierGenerator();
			authnRequest.setID(generator.generateIdentifier());
		} catch (NoSuchAlgorithmException ex) {
			ex.printStackTrace();
		}

		authnRequest.setVersion(SAMLVersion.VERSION_20);
		authnRequest.setIssueInstant(new DateTime());
		authnRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		authnRequest.setDestination("https://idpiot.cafeexpresso.rnp.br/simplesaml/saml2/idp/SSOService.php");

		NameIDPolicy nameIDpolicy = this.create(NameIDPolicy.class, NameIDPolicy.DEFAULT_ELEMENT_NAME);
		nameIDpolicy.setAllowCreate(Boolean.TRUE);
		nameIDpolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");

		authnRequest.setNameIDPolicy(nameIDpolicy);

		Issuer issuer = this.create(Issuer.class, Issuer.DEFAULT_ELEMENT_NAME);
		issuer.setValue("https://37.48.106.66/simplesaml/module.php/saml/sp/metadata.php/default-sp");
		// issuer.setValue("sp2.gidlab.rnp.br");
		authnRequest.setIssuer(issuer);

		return authnRequest;
	}

	/**
	 * Serializes the instance of the authnRequest object received as a parameter to
	 * an XML instance (org.w3c.dom.Element)
	 *
	 * @param authnRequest
	 *            Authentication request that will be serialized in XML
	 * @see org.opensaml.saml2.core.AuthnRequest
	 * @return the element Authentication request represented in XML
	 */
	public Element authnRequestToXML(AuthnRequest authnRequest) {
		Element output = null;
		try {
			AuthnRequestMarshaller marshaller = new AuthnRequestMarshaller();
			output = marshaller.marshall(authnRequest);
		} catch (MarshallingException ex) {
			ex.printStackTrace();
		}
		return output;
	}

	/**
	 * Creates and return objects using QN (qualified name) through the factory
	 * org.opensaml.xml.XMLObjectBuilder
	 * 
	 * @see https://www.w3.org/TR/xmlschema-2/#QName
	 *
	 * @param cls
	 *            The class to create
	 * @param qname
	 *            Qualified name. This key is either the XML Schema Type or element
	 *            QName of the XML element the built XMLObject object represents.
	 *            {@link javax.xml.namespace.QName}
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	private <T> T create(Class<T> cls, QName qname) {
		return (T) ((XMLObjectBuilder) Configuration.getBuilderFactory().getBuilder(qname)).buildObject(qname);
	}

}
