package org.soulwing.cas.elytron;

import static org.soulwing.cas.elytron.CASAuthenticationMechanismFactory.METHOD_NAME;
import static org.wildfly.security.http.HttpConstants.DISABLE_SESSION_ID_CHANGE;

import java.io.IOException;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.wildfly.security.auth.callback.AuthenticationCompleteCallback;
import org.wildfly.security.auth.callback.CachedIdentityAuthorizeCallback;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.cache.CachedIdentity;
import org.wildfly.security.cache.IdentityCache;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpConstants;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerAuthenticationMechanism;
import org.wildfly.security.http.HttpServerMechanismsResponder;
import org.wildfly.security.http.HttpServerRequest;
import org.wildfly.security.http.Scope;

public class CASAuthenticationMechanism
		implements HttpServerAuthenticationMechanism {

	private static final String CACHED_IDENTITY_KEY =
			CASAuthenticationMechanism.class.getName() + ".elytron-identity";

	private final CallbackHandler callbackHandler;
	private final boolean disableSessionIdChange;

	public CASAuthenticationMechanism(CallbackHandler callbackHandler,
			final Map<String, ?> properties) {
		this.callbackHandler = callbackHandler;
		disableSessionIdChange = Boolean.parseBoolean(
				(String) properties.get(DISABLE_SESSION_ID_CHANGE));
	}

	@Override
	public String getMechanismName() {
		return METHOD_NAME;
	}

	@Override
	public void evaluateRequest(HttpServerRequest request)
			throws HttpAuthenticationException {

		TicketEvidenceVerifyCallback verifyCallback = validateTicket(request);

		if (verifyCallback.wasAuthenticationAttempted()) {
			if (authenticated(verifyCallback)) {
				if (authorized(request, verifyCallback)) {
					authSucceeded(request, verifyCallback.getPostAuthUrl());
				} else {
					authFailed(request);
				}
			} else {
				authFailed(request);
			}
		} else {
			if (previouslyAuthorized(request)) {
				authSucceeded(request, null);
			} else {
				challenge(request, verifyCallback.getLoginUrl());
			}
		}

	}

	public TicketEvidenceVerifyCallback validateTicket(
			HttpServerRequest request) throws HttpAuthenticationException {
		TicketEvidenceVerifyCallback verifyCallback = new TicketEvidenceVerifyCallback(
				new TicketEvidence(request));
		try {
			callbackHandler.handle(new Callback[] { verifyCallback });
		} catch (IOException | UnsupportedCallbackException e) {
			throw new HttpAuthenticationException(e);
		}
		return verifyCallback;
	}

	public boolean authenticated(TicketEvidenceVerifyCallback verifyCallback) {
		return verifyCallback.isVerified();
	}

	public boolean authorized(HttpServerRequest request,
			TicketEvidenceVerifyCallback verifyCallback)
			throws HttpAuthenticationException {
		IdentityCache identityCache = createIdentityCache(request);
		String username = verifyCallback.getIdentityAssertion().getPrincipal()
				.getName();
		CachedIdentityAuthorizeCallback authorizeCallback = new CachedIdentityAuthorizeCallback(
				username, identityCache);
		try {
			callbackHandler.handle(new Callback[] { authorizeCallback });
			return authorizeCallback.isAuthorized();
		} catch (IOException | UnsupportedCallbackException e) {
			throw new HttpAuthenticationException(e);
		}
	}

	public boolean previouslyAuthorized(HttpServerRequest request)
			throws HttpAuthenticationException {
		IdentityCache identityCache = createIdentityCache(request);
		CachedIdentityAuthorizeCallback authorizeCallback = new CachedIdentityAuthorizeCallback(
				identityCache);
		try {
			callbackHandler.handle(new Callback[] { authorizeCallback });
			return authorizeCallback.isAuthorized();
		} catch (IOException | UnsupportedCallbackException e) {
			throw new HttpAuthenticationException(e);
		}
	}

	private HttpServerMechanismsResponder failedResponse() {
		return response -> response.setStatusCode(HttpConstants.UNAUTHORIZED);
	}

	private void authSucceeded(HttpServerRequest request, String redirectUrl)
			throws HttpAuthenticationException {
		try {
			IdentityCache identityCache = createIdentityCache(request);
			callbackHandler.handle(new Callback[] {
					AuthenticationCompleteCallback.SUCCEEDED });
			request.authenticationComplete(
					redirectUrl == null ? null : getRedirect(redirectUrl),
					identityCache::remove);
		} catch (IOException | UnsupportedCallbackException e) {
			throw new HttpAuthenticationException(e);
		}
	}

	private void challenge(HttpServerRequest request, String loginUrl) {
		request.noAuthenticationInProgress(getRedirect(loginUrl));
	}

	private void authFailed(HttpServerRequest request)
			throws HttpAuthenticationException {
		try {
			IdentityCache identityCache = createIdentityCache(request);
			identityCache.remove();
			callbackHandler.handle(
					new Callback[] { AuthenticationCompleteCallback.FAILED });
			request.authenticationFailed("Not authorized", failedResponse());
		} catch (IOException | UnsupportedCallbackException e) {
			throw new HttpAuthenticationException(e);
		}
	}

	private HttpServerMechanismsResponder getRedirect(String url) {
		return response -> {
			response.setStatusCode(HttpConstants.FOUND);
			response.addResponseHeader(HttpConstants.LOCATION, url);
		};
	}

	/**
	 * IdentityCache copied from org.wildfly.security.http.form.FormAuthenticationMechanism
	 *
	 * @param request
	 * @return
	 */
	private IdentityCache createIdentityCache(HttpServerRequest request) {
		return new IdentityCache() {
			@Override
			public void put(SecurityIdentity identity) {
				HttpScope session = getSessionScope(request, true);

				if (session == null || !session.exists()) {
					return;
				}

				/*
				 * If we are associating an identity with the session for the first time we need to
				 * change the ID of the session, in other cases we can continue with the same ID.
				 */
				if (!disableSessionIdChange && session.supportsChangeID()
						&& session.getAttachment(CACHED_IDENTITY_KEY) == null) {
					session.changeID();
				}

				session.setAttachment(CACHED_IDENTITY_KEY,
						new CachedIdentity(getMechanismName(), false,
								identity));
			}

			@Override
			public CachedIdentity get() {
				HttpScope session = getSessionScope(request, false);

				if (session == null || !session.exists()) {
					return null;
				}

				return (CachedIdentity) session.getAttachment(
						CACHED_IDENTITY_KEY);
			}

			@Override
			public CachedIdentity remove() {
				HttpScope session = getSessionScope(request, false);

				if (session == null || !session.exists()) {
					return null;
				}

				CachedIdentity cachedIdentity = get();

				session.setAttachment(CACHED_IDENTITY_KEY, null);

				return cachedIdentity;
			}
		};
	}

	private HttpScope getSessionScope(HttpServerRequest request,
			boolean createSession) {
		HttpScope scope = request.getScope(Scope.SESSION);

		if (scope != null && !scope.exists() && createSession) {
			scope.create();
		}

		return scope;
	}

}
