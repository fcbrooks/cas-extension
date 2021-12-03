package org.soulwing.cas.elytron;

import static org.soulwing.cas.elytron.ElytronLogger.LOGGER;

import java.net.URI;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.soulwing.cas.api.IdentityAssertion;
import org.soulwing.cas.api.Transformer;
import org.soulwing.cas.service.AuthenticationException;
import org.soulwing.cas.service.AuthenticationProtocol;
import org.soulwing.cas.service.Authenticator;
import org.soulwing.cas.service.AuthenticatorFactory;
import org.soulwing.cas.service.Configuration;
import org.soulwing.cas.service.NoTicketException;
import org.soulwing.cas.service.ProxyCallbackHandlerFactory;
import org.soulwing.cas.ssl.HostnameVerifierFactory;
import org.soulwing.cas.ssl.HostnameVerifierType;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SecurityRealm;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.http.HttpServerRequest;

public class CASSecurityRealm implements SecurityRealm {

	private Configuration configuration;
	private String roleAttribute;

	public void initialize(Map<String, String> realmConfig) {
		this.configuration = new RealmConfig(realmConfig);
		roleAttribute = realmConfig.getOrDefault("role-attribute", "");
	}

	@Override
	public SupportLevel getCredentialAcquireSupport(
			Class<? extends Credential> credentialType, String algorithmName,
			AlgorithmParameterSpec parameterSpec)
			throws RealmUnavailableException {
		return SupportLevel.UNSUPPORTED;
	}

	@Override
	public SupportLevel getEvidenceVerifySupport(
			Class<? extends Evidence> evidenceType, String algorithmName)
			throws RealmUnavailableException {
		return evidenceType.isAssignableFrom(TicketEvidence.class) ?
				SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
	}

	@Override
	public RealmIdentity getRealmIdentity(Principal principal)
			throws RealmUnavailableException {
		return SecurityRealm.super.getRealmIdentity(principal);
	}

	@Override
	public RealmIdentity getRealmIdentity(Evidence evidence)
			throws RealmUnavailableException {
		return new RealmIdentity() {

			@Override
			public AuthorizationIdentity getAuthorizationIdentity()
					throws RealmUnavailableException {
				Map<String, Object> principalAttributes = assertion.getPrincipal()
						.getAttributes();
				Set<String> roles = new TreeSet<>();
				if (principalAttributes.containsKey(roleAttribute)) {
					Object rawPrincipleAttributes = principalAttributes.get(
							roleAttribute);
					if (rawPrincipleAttributes instanceof List) {
						@SuppressWarnings("unchecked")
						List<String> principalAttribute = (List<String>) rawPrincipleAttributes;
						roles.addAll(principalAttribute);
					} else {
						LOGGER.warn(
								"Role attribute needs to return a list of strings");
					}
				}
				Map<String, Set<String>> attributes = new HashMap<>();
				attributes.put(roleAttribute, roles);
				return AuthorizationIdentity.basicIdentity(
						new MapAttributes(attributes));
			}

			private IdentityAssertion assertion;

			@Override
			public Principal getRealmIdentityPrincipal() {
				return assertion != null ?
						new NamePrincipal(assertion.getPrincipal().getName()) :
						null;
			}

			@Override
			public SupportLevel getCredentialAcquireSupport(
					Class<? extends Credential> credentialType,
					String algorithmName, AlgorithmParameterSpec parameterSpec)
					throws RealmUnavailableException {
				return SupportLevel.UNSUPPORTED;
			}

			@Override
			public <C extends Credential> C getCredential(
					Class<C> credentialType) throws RealmUnavailableException {
				return null;
			}

			@Override
			public SupportLevel getEvidenceVerifySupport(
					Class<? extends Evidence> evidenceType,
					String algorithmName) throws RealmUnavailableException {
				return evidenceType.isAssignableFrom(TicketEvidence.class) ?
						SupportLevel.POSSIBLY_SUPPORTED :
						SupportLevel.UNSUPPORTED;
			}

			@Override
			public boolean verifyEvidence(Evidence evidence)
					throws RealmUnavailableException {

				if (evidence instanceof TicketEvidence) {

					TicketEvidence requestEvidence = (TicketEvidence) evidence;

					HttpServerRequest request = requestEvidence.getRequest();

					Authenticator authenticator = AuthenticatorFactory.newInstance(
							configuration,
							proxyCallbackUrl(contextRoot(request)),
							ProxyCallbackHandlerFactory.newInstance());

					if (!request.getParameterNames().contains(
							configuration.getProtocol()
									.getTicketParameterName())) {
						return authNotInProgress(authenticator,
								requestEvidence);
					}

					try {
						URI uri = request.getRequestURI();
						assertion = authenticator.validateTicket(uri.getPath(),
								checkNull(uri.getQuery(), ""));
						requestEvidence.setAuthenticationAttempted(
								assertion.isValid());
						requestEvidence.setIdentityAssertion(assertion);
						requestEvidence.setPostAuthUrl(
								configuration.isPostAuthRedirect() ?
										authenticator.postAuthUrl(uri.getPath(),
												checkNull(uri.getQuery(), "")) :
										null);
						return assertion.isValid();
					} catch (NoTicketException e) {
						return authNotInProgress(authenticator,
								requestEvidence);
					} catch (AuthenticationException e) {
						throw new RealmUnavailableException(e);
					}

				}

				return false;
			}

			@Override
			public boolean exists() throws RealmUnavailableException {
				return assertion.isValid();
			}
		};
	}

	private boolean authNotInProgress(Authenticator authenticator,
			TicketEvidence requestEvidence) {
		URI uri = requestEvidence.getRequest().getRequestURI();
		requestEvidence.setAuthenticationAttempted(false);
		requestEvidence.setLoginUrl(authenticator.loginUrl(uri.getPath(),
				checkNull(uri.getQuery(), "")));
		return false;
	}

	private <T> T checkNull(T value, T nullValue) {
		return Optional.ofNullable(value).orElse(nullValue);
	}

	private static class RealmConfig implements Configuration {

		private final Map<String, String> realmConfig;

		public RealmConfig(Map<String, String> realmConfig) {
			this.realmConfig = realmConfig;
		}

		@Override
		public AuthenticationProtocol getProtocol() {
			String protocol = realmConfig.getOrDefault("protocol",
					AuthenticationProtocol.CAS1_0.name());
			return AuthenticationProtocol.toObject(protocol);
		}

		@Override
		public String getEncoding() {
			return realmConfig.getOrDefault("encoding", "UTF-8");
		}

		@Override
		public String getServerUrl() {
			return realmConfig.get("server-url");
		}

		@Override
		public String getServiceUrl() {
			return realmConfig.get("service-url");
		}

		@Override
		public boolean isProxyCallbackEnabled() {
			return Boolean.parseBoolean(
					realmConfig.getOrDefault("proxy-callback-enabled",
							"false"));
		}

		@Override
		public String getProxyCallbackPath() {
			return realmConfig.getOrDefault("proxy-callback-path",
					"/casProxyCallback");
		}

		@Override
		public boolean isAcceptAnyProxy() {
			return Boolean.parseBoolean(
					realmConfig.getOrDefault("accept-any-proxy", "false"));
		}

		@Override
		public boolean isAllowEmptyProxyChain() {
			return Boolean.parseBoolean(
					realmConfig.getOrDefault("allow-empty-proxy-chain",
							"false"));
		}

		@Override
		public List<String[]> getAllowedProxyChains() {
			return null;
		}

		@Override
		public boolean isProxySupported() {
			return false;
		}

		@Override
		public String getOriginalRequestPathHeader() {
			return null;
		}

		@Override
		public boolean isRenew() {
			return Boolean.parseBoolean(
					realmConfig.getOrDefault("renew", "false"));
		}

		@Override
		public long getClockSkewTolerance() {
			return Long.parseLong(
					realmConfig.getOrDefault("clock-skew-tolerance", "1000"));
		}

		@Override
		public boolean isPostAuthRedirect() {
			return Boolean.parseBoolean(
					realmConfig.getOrDefault("post-auth-redirect", "true"));
		}

		@Override
		public boolean isCasStatusCookieEnabled() {
			return Boolean.parseBoolean(
					realmConfig.getOrDefault("cas-status-cookie-enabled",
							"true"));
		}

		@Override
		public SSLContext getSslContext() {
			SSLContext ctx = null;
			try {
				ctx = SSLContext.getInstance("TLS");
				TrustManager[] certs = new TrustManager[] {
						new X509TrustManager() {
							@Override
							public void checkClientTrusted(
									X509Certificate[] chain, String authType)
									throws CertificateException {
							}

							@Override
							public void checkServerTrusted(
									X509Certificate[] chain, String authType)
									throws CertificateException {
							}

							@Override
							public X509Certificate[] getAcceptedIssuers() {
								return new X509Certificate[0];
							}
						} };
				ctx.init(null, certs, new SecureRandom());
			} catch (NoSuchAlgorithmException | KeyManagementException e) {
				e.printStackTrace();
			}
			return ctx;
		}

		@Override
		public HostnameVerifier getHostnameVerifier() {
			return HostnameVerifierFactory.newInstance(
					HostnameVerifierType.ALLOW_ANY);
		}

		@Override
		public Map<String, Transformer<Object, Object>> getAttributeTransformers() {
			return new HashMap<>();
		}
	}

	private String contextRoot(HttpServerRequest request) {
		return "/" + Arrays.stream(request.getRequestURI().getPath().split("/"))
				.collect(Collectors.toList()).get(1);
	}

	private String proxyCallbackUrl(String contextPath) {
		if (configuration.getProxyCallbackPath() == null)
			return null;
		URI uri = URI.create(configuration.getServiceUrl());
		StringBuilder sb = new StringBuilder();
		sb.append(uri.getScheme());
		sb.append("://");
		sb.append(uri.getAuthority());
		sb.append(contextPath);
		String proxyCallbackPath = configuration.getProxyCallbackPath();
		if (!proxyCallbackPath.startsWith("/") && !contextPath.endsWith("/")) {
			sb.append("/");
		}
		sb.append(proxyCallbackPath);
		return sb.toString();
	}

}
