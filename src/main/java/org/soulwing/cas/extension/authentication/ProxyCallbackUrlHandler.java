/*
 * File created on Dec 15, 2014 
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
package org.soulwing.cas.extension.authentication;

import org.jboss.as.controller.OperationFailedException;
import org.jboss.dmr.ModelNode;
import org.soulwing.cas.service.authentication.MutableConfiguration;

/** 
 * A write attribute handler for proxy callback URL attribute.
 *
 * @author Carl Harris
 */
class ProxyCallbackUrlHandler 
    extends AbstractAuthenticationAttributeHandler<Void> {

  static final ProxyCallbackUrlHandler INSTANCE =
      new ProxyCallbackUrlHandler();
  
  private ProxyCallbackUrlHandler() {
    super(AuthenticationDefinition.PROXY_CALLBACK_URL);
  }
  
  /**
   * {@inheritDoc}
   */
  @Override
  protected Void applyUpdateToConfiguration(String attributeName,
      ModelNode value, MutableConfiguration config)
      throws OperationFailedException {
    config.setProxyCallbackUrl(value.resolve().asString());
    return null;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  protected void revertUpdateToConfiguration(String attributeName,
      ModelNode value, MutableConfiguration config, Void handback)
      throws OperationFailedException {
    config.setProxyCallbackUrl(value.resolve().asString());
  }

}
