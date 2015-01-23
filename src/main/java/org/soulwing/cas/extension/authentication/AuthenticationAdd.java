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

import java.util.List;

import org.jboss.as.controller.AbstractAddStepHandler;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.ServiceVerificationHandler;
import org.jboss.as.controller.descriptions.ModelDescriptionConstants;
import org.jboss.dmr.ModelNode;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceController.Mode;
import org.jboss.msc.service.ServiceName;
import org.soulwing.cas.extension.SubsystemExtension;
import org.soulwing.cas.service.authentication.AuthenticationProtocol;
import org.soulwing.cas.service.authentication.AuthenticationService;
import org.soulwing.cas.service.authentication.AuthenticationServiceFactory;
import org.soulwing.cas.service.authentication.MutableConfiguration;

/**
 * An add step handler for the authentication resource.
 *
 * @author Carl Harris
 */
class AuthenticationAdd extends AbstractAddStepHandler {

  public static final AuthenticationAdd INSTANCE = 
      new AuthenticationAdd();
  
  private AuthenticationAdd() {    
  }

  /**
   * {@inheritDoc}
   */
  @Override
  protected void populateModel(ModelNode operation, ModelNode model)
      throws OperationFailedException {
    SubsystemExtension.logger.info("populating model for authentication resource");
    AuthenticationDefinition.PROTOCOL.validateAndSet(operation, model);
    AuthenticationDefinition.SERVICE_URL.validateAndSet(operation, model);
    AuthenticationDefinition.SERVER_URL.validateAndSet(operation, model);
    AuthenticationDefinition.PROXY_CALLBACK_URL.validateAndSet(operation, model);
    AuthenticationDefinition.ACCEPT_ANY_PROXY.validateAndSet(operation, model);
    AuthenticationDefinition.ALLOW_EMPTY_PROXY_CHAIN.validateAndSet(operation, model);
    AuthenticationDefinition.RENEW.validateAndSet(operation, model);
    super.populateModel(operation, model);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  protected void performRuntime(OperationContext context,
      ModelNode operation, ModelNode model,
      ServiceVerificationHandler verificationHandler,
      List<ServiceController<?>> newControllers)
      throws OperationFailedException {
    
    ServiceName serviceName = AuthenticationServiceControl.name(
        operation.get(ModelDescriptionConstants.ADDRESS));
    
    AuthenticationService service = AuthenticationServiceFactory.newInstance();
    MutableConfiguration config = service.getConfiguration().clone();
    applyConfiguration(context, model, config);
    service.reconfigure(config);
    
    ServiceController<AuthenticationService> controller = context
        .getServiceTarget()
        .addService(serviceName, new AuthenticationServiceControl(service))
        .addListener(verificationHandler)
        .setInitialMode(Mode.ACTIVE)
        .install();
    
    SubsystemExtension.logger.info("added authentication service " + serviceName);

    newControllers.add(controller);
    super.performRuntime(context, operation, model, verificationHandler,
        newControllers);
  }

  private MutableConfiguration applyConfiguration(OperationContext context,
      ModelNode model, MutableConfiguration config) 
          throws OperationFailedException {
    config.setProtocol(AuthenticationProtocol.toObject(AuthenticationDefinition.PROTOCOL.resolveModelAttribute(context, model).asString()));
    config.setServerUrl(AuthenticationDefinition.SERVER_URL
        .resolveModelAttribute(context, model).asString());
    config.setServiceUrl(AuthenticationDefinition.SERVICE_URL
        .resolveModelAttribute(context, model).asString());
    config.setProxyCallbackUrl(AuthenticationDefinition.PROXY_CALLBACK_URL
        .resolveModelAttribute(context, model).asString());
    config.setAcceptAnyProxy(AuthenticationDefinition.ACCEPT_ANY_PROXY
        .resolveModelAttribute(context, model).asBoolean());
    config.setAllowEmptyProxyChain(AuthenticationDefinition.ALLOW_EMPTY_PROXY_CHAIN
        .resolveModelAttribute(context, model).asBoolean());
    config.setRenew(AuthenticationDefinition.RENEW
        .resolveModelAttribute(context, model).asBoolean());
    return config;
  }
  
}
