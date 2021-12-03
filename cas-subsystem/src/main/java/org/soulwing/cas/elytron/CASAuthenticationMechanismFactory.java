package org.soulwing.cas.elytron;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;

import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

public class CASAuthenticationMechanismFactory
		implements HttpServerAuthenticationMechanismFactory {

	static final String METHOD_NAME = "CAS";

	@Override
	public String[] getMechanismNames(Map<String, ?> properties) {
		return new String[] { METHOD_NAME };
	}

	@Override
	public HttpServerAuthenticationMechanism createAuthenticationMechanism(
			String mechanismName, Map<String, ?> properties,
			CallbackHandler callbackHandler)
			throws HttpAuthenticationException {
		if (METHOD_NAME.equals(mechanismName)) {
			return new CASAuthenticationMechanism(callbackHandler, properties);
		}
		return null;
	}
}
