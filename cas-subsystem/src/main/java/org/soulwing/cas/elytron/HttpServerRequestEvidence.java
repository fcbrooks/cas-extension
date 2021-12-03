package org.soulwing.cas.elytron;

import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.http.HttpServerRequest;

public class HttpServerRequestEvidence implements Evidence {

	private final HttpServerRequest request;

	public HttpServerRequestEvidence(HttpServerRequest request) {
		this.request = request;
	}

	public HttpServerRequest getRequest() {
		return request;
	}
}
