/*
 * File created on Dec 18, 2014 
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
package org.soulwing.cas.extension;

import org.jboss.as.controller.SimpleAttributeDefinition;

/**
 * An XML reader/writer for the configuration profile resource.
 *
 * @author Carl Harris
 */
public class ProfileReaderWriter extends AbstractResourceReaderWriter {
  
  /**
   * Constructs a new instance.
   */
  public ProfileReaderWriter() {
    super(Names.CAS_PROFILE, new HostnameVerifierReaderWriter(),
        new ProxyChainReaderWriter(), new AttributeTransformReaderWriter());
  }

  /**
   * {@inheritDoc}
   */
  @Override
  protected SimpleAttributeDefinition[] attributes() {
    return new SimpleAttributeDefinition[] { 
        ProfileDefinition.PROTOCOL,
        ProfileDefinition.ENCODING,
        ProfileDefinition.SERVICE_URL,
        ProfileDefinition.SERVER_URL,
        ProfileDefinition.PROXY_CALLBACK_ENABLED,
        ProfileDefinition.PROXY_CALLBACK_PATH,
        ProfileDefinition.ACCEPT_ANY_PROXY,
        ProfileDefinition.ALLOW_EMPTY_PROXY_CHAIN,
        ProfileDefinition.RENEW,
        ProfileDefinition.CLOCK_SKEW_TOLERANCE,
        ProfileDefinition.POST_AUTH_REDIRECT,
        ProfileDefinition.SECURITY_REALM,
        ProfileDefinition.CAS_STATUS_COOKIE_ENABLED
    };
  }
  
}
