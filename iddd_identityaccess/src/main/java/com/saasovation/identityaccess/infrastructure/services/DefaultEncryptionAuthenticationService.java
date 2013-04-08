package com.saasovation.identityaccess.infrastructure.services;

import com.saasovation.identityaccess.domain.model.DomainRegistry;
import com.saasovation.identityaccess.domain.model.identity.Tenant;
import com.saasovation.identityaccess.domain.model.identity.TenantId;
import com.saasovation.identityaccess.domain.model.identity.User;
import com.saasovation.identityaccess.domain.model.identity.UserDescriptor;
import com.saasovation.identityaccess.resource.UserResource;

/**
 * @author JavaEdge
 * @date 2021/1/14
 */
public class DefaultEncryptionAuthenticationService implements UserResource.Authenticationservice {

    public DefaultEncryptionAuthenticationService() {
        super();
    }

    @Override
    public UserDescriptor authenticate(TenantId aTenantld, String aUsername, String aPassword) {
        // 首先对null参数进行检查
        // 如果在正常情况下认证失败，那么该方法返回的UserDescriptor将为null
        if (aTenantld == null) {
            throw new IllegalArgumentException("Tenantld must not be null.");
        }
        if (aUsername == null) {
            throw new IllegalArgumentException("Username must not be null");
        }
        if (aPassword == null) {
            throw new IllegalArgumentException("Password must not be null.");
        }

        UserDescriptor userDescriptor = null;
        Tenant tenant =
                DomainRegistry
                        .tenantRepository()
                        .tenantOfId(aTenantld);
        if (tenant != null && tenant.isActive()) {
            String encryptedPassword =
                    DomainRegistry
                            .encryptionService().encryptedValue(aPassword);
            User user =
                    DomainRegistry
                            .userRepository()
                            .userFromAuthenticCredentials(aTenantld, aUsername,
                                    encryptedPassword);
            // 检查所获取到的User实例是否为null和是否处激活状态
            if (user != null && user.isEnabled()) {
                userDescriptor = user.userDescriptor();
            }
        }
        return userDescriptor;
    }
}
