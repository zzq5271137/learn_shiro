package com.mycomp;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import java.util.ArrayList;
import java.util.List;

/*
 * 从数据库中获取认证信息, 需要自定义Realm;
 * 然后需要去ini配置文件中进行配置(详见shiro.ini);
 */

public class MyRealm extends AuthorizingRealm {
    private static final String ROLE_1 = "role1";
    private static final String ROLE_2 = "role2";
    private static final String ROLE_3 = "role3";
    private static final String USER_CREATE = "user:create";
    private static final String USER_UPDATE = "user:update";
    private static final String USER_DELETE = "user:delete";
    private static final String USER_EDIT = "user:edit";

    /**
     * 认证
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
            throws AuthenticationException {
        String salt = "feiwu";

        // 获取身份信息
        String username = (String) token.getPrincipal();

        // 从数据库中查出用户名和密码(这里先写死)
        String usernameDB = "zzq";
        // String passwordDB = "zzqgo";
        String passwordDB = "0f7c76eb7e2666f25aadabe11b7cd8f2"; // 加密后的密码, 详见App.java中的registerTest()

        // 判断当前用户是否存在
        if (!username.equals(usernameDB)) {
            return null;
        }

        // 交由认证器去认证(需要传入salt信息)
        return new SimpleAuthenticationInfo(
                username,
                passwordDB,
                ByteSource.Util.bytes(salt),
                this.getName());
    }

    /**
     * 授权
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        // 获取当前用户的身份信息
        Object primaryPrincipal = principals.getPrimaryPrincipal();

        // 根据身份信息, 到数据库中查询该用户有哪些角色和权限(这里先写死)
        List<String> roles = new ArrayList<>();
        roles.add(ROLE_1);
        roles.add(ROLE_2);
        List<String> permissions = new ArrayList<>();
        permissions.add(USER_CREATE);
        permissions.add(USER_UPDATE);
        permissions.add(USER_DELETE);

        // 把从数据库中查到的改用户拥有的角色和权限添加到授权中
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.addRoles(roles);
        info.addStringPermissions(permissions);

        return info;
    }

}
