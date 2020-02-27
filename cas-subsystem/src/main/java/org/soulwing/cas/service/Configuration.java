/*
 * File created on Dec 24, 2014 
 *
 * Copyright (c) 2015 Carl Harris, Jr.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package org.soulwing.cas.service;

import java.nio.file.attribute.UserPrincipal;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;

import org.soulwing.cas.api.Transformer;

/**
 * An (immutable) configuration for an {@link Authenticator}.
 *
 * @author Carl Harris
 */
public interface Configuration {

  /**
   * Gets the protocol.
   * @return protocol
   */
  AuthenticationProtocol getProtocol();  
  
  /**
   * Gets the character encoding.
   * @return character encoding
   */
  String getEncoding();

  /**
   * Gets the CAS server URL.
   * @return server URL
   */
  String getServerUrl();
  
  /**
   * Gets the application service URL.
   * @return service URL
   */
  String getServiceUrl();
  
  /**
   * Gets a flag that indicates whether a proxy granting ticket should be
   * requested with each authentication request.
   * @return
   */
  boolean isProxyCallbackEnabled();
  
  /**
   * Gets the CAS proxy callback path.
   * @return proxy callback path
   */
  String getProxyCallbackPath();
  
  /**
   * Gets a flag indicating whether any proxy should be accepted in a
   * proxy ticket validation.
   * @return flag state
   */
  boolean isAcceptAnyProxy();
  
  /**
   * Gets a flag indicating whether an empty proxy chain should be accepted
   * in a proxy ticket validation.
   * @return flag state
   */
  boolean isAllowEmptyProxyChain();
  
  /**
   * Gets the list of proxy chains that should be allowed in a proxy ticket
   * validation.
   * @return list of proxy chains
   */
  List<String[]> getAllowedProxyChains();

  /**
   * Determines whether this configuration supports proxy ticket validation.
   * @return {@code true} if this configuration supports proxy ticket validation
   */
  boolean isProxySupported();

  /**
   * Gets the name of an HTTP header that is used to store the original request
   * path when running behind a reverse proxy.
   * @return request header name or {@code null} if none has been set
   */
  String getOriginalRequestPathHeader();

  /**
   * Gets a flag indicating whether the user should be compelled to 
   * re-authenticate.
   * @return flag state
   */
  boolean isRenew();
  
  /**
   * Gets the amount of time-of-day clock skew that is considered acceptable
   * when evaluating the validity of SAML responses.
   * @return skew tolerance in milliseconds
   */
  long getClockSkewTolerance();
  
  /**
   * Gets a flag indicating whether, after a successful ticket validation, an
   * additional redirect should be sent to the user's browser to remove 
   * protocol-related parameters from the query string.
   * @return flag state
   */
  boolean isPostAuthRedirect();

  /**
   * Gets a flag that indicates whether tracking the login attempts
   * with the 'cas-status' cookie is enabled.
   * @return flag state
   */
  boolean isCasStatusCookieEnabled();

  /**
   * Gets the SSL context to use in negotiations with the CAS server.
   * @return SSL context or {@code null} to indicate that the default SSL
   *    context is to be used
   */
  SSLContext getSslContext();
  
  /**
   * Gets the hostname verifier to be used to verify the name of the CAS
   * server (e.g. to workaround mismatches between server name and the name
   * on the server's X.509 certificate).
   * @return hostname verifier or {@code null} to indicate that the default
   *    hostname verifier is to be used
   */
  HostnameVerifier getHostnameVerifier();

  /**
   * Gets the identity assertion attribute transformers associated with this 
   * configuration.
   * <p>
   * The keys of the returned map correspond to the names of attributes that
   * may be appear in the {@link UserPrincipal} after a successful 
   * authentication.  The corresponding value is a function that should be
   * applied to each attribute of the given name to transform the value in
   * some manner. 
   * @return attribute transformer map
   */
  Map<String, Transformer<Object, Object>> getAttributeTransformers();
  
}
