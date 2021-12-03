package org.soulwing.cas.elytron;

import org.soulwing.cas.api.IdentityAssertion;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.http.HttpServerMechanismsResponder;

public class TicketEvidenceVerifyCallback extends EvidenceVerifyCallback {

	private final TicketEvidence evidence;
	private HttpServerMechanismsResponder authResponder;

	/**
	 * Construct a new instance of this {@link Callback}.
	 *
	 * @param evidence the evidence to be verified
	 */
	public TicketEvidenceVerifyCallback(TicketEvidence evidence) {
		super(evidence);
		this.evidence = evidence;
	}

	public boolean wasAuthenticationAttempted() {
		return evidence.isAuthenticationAttempted();
	}

	public String getLoginUrl() {
		return evidence.getLoginUrl();
	}

	public String getPostAuthUrl() {
		return evidence.getPostAuthUrl();
	}

	public IdentityAssertion getIdentityAssertion() {
		return evidence.getIdentityAssertion();
	}

}
