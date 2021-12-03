package org.soulwing.cas.elytron;

import org.soulwing.cas.api.IdentityAssertion;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.http.HttpServerMechanismsResponder;
import org.wildfly.security.http.HttpServerRequest;

public class TicketEvidence extends HttpServerRequestEvidence {

	private boolean authenticationAttempted;
	private String loginUrl;
	private String postAuthUrl;
	private IdentityAssertion identityAssertion;

	public TicketEvidence(HttpServerRequest httpServerRequest) {
		super(httpServerRequest);
	}

	public boolean isAuthenticationAttempted() {
		return authenticationAttempted;
	}

	public void setAuthenticationAttempted(boolean authenticationAttempted) {
		this.authenticationAttempted = authenticationAttempted;
	}

	public String getLoginUrl() {
		return loginUrl;
	}

	public void setLoginUrl(String loginUrl) {
		this.loginUrl = loginUrl;
	}

	public String getPostAuthUrl() {
		return postAuthUrl;
	}

	public void setPostAuthUrl(String postAuthUrl) {
		this.postAuthUrl = postAuthUrl;
	}

	public IdentityAssertion getIdentityAssertion() {
		return identityAssertion;
	}

	public void setIdentityAssertion(IdentityAssertion identityAssertion) {
		this.identityAssertion = identityAssertion;
	}
}
