package com.mycomp;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;

import java.util.Arrays;

public class App {
    public static void main(String[] args) {
        // shiroAuthenticationTest();
        // encryptionTest();
        shiroAuthorizationTest();
    }

    /**
     * Shiro认证流程
     */
    private static void shiroAuthenticationTest() {
        // 用户输入
        String username = "zzq";
        String password = "zzqgo";

        // 1. 构建SecurityManager工厂, 加载ini文件(@deprecated, 过期方法)
        // IniSecurityManagerFactory factory = new IniSecurityManagerFactory("classpath:shiro-ini.ini");
        IniSecurityManagerFactory factory = new IniSecurityManagerFactory("classpath:shiro.ini");

        // 2. 通过工厂创建SecurityManager
        SecurityManager securityManager = factory.getInstance();

        // 3. 将SecurityManager设置到运行环境中
        SecurityUtils.setSecurityManager(securityManager);

        // 4. 创建一个Subject实例
        Subject subject = SecurityUtils.getSubject();

        // 5. 创建token令牌(在实际应用中, token令牌应该是由文本框输入的, 如登录的用户名和密码)
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        /*
         * 密码经过加密后, 保存到数据库;
         * 在用户登录时, 用户输入的明文密码也需要经过相同的加密处理, 才能够与从数据库取出的密文密码进行比对;
         * 只需要在ini配置文件中进行设置, Shiro就会自动的对用户输入的明文密码进行相应的加密处理;
         * ini配置文件中的凭证匹配器配置, 其加密参数需要与用户注册时的加密参数一样, 详见shiro.ini;
         * salt信息, 需要在自定义realm中进行设置, 详见MyRealm.java中的doGetAuthenticationInfo();
         */

        // 6. 用户登录
        System.out.println("用户登录...");
        try {
            subject.login(token);
        } catch (UnknownAccountException e) {
            System.out.println("账号不存在");
            e.printStackTrace();
        } catch (IncorrectCredentialsException e) {
            System.out.println("密码错误");
            e.printStackTrace();
        }
        System.out.println("该用户是否认证成功: " + subject.isAuthenticated());

        // 7. 用户退出
        System.out.println("用户退出...");
        subject.logout();

        System.out.println("该用户是否认证成功: " + subject.isAuthenticated());
    }

    /**
     * Shiro加密(散列): MD5或SHA的加密方式
     */
    private static void encryptionTest() {
        String password = "zzqgo";

        /*
         * MD5加密
         */
        Md5Hash md5HashPassword1 = new Md5Hash(password);
        System.out.println(md5HashPassword1);

        /*
         * 加盐:
         * 同样的字符串每次加密之后的结果都一样, 这样会造成安全漏洞, 所以在加密时, 我们通常加一个标识(盐)
         */
        String salt = "feiwu";
        Md5Hash md5HashPassword2 = new Md5Hash(password, salt);
        System.out.println(md5HashPassword2);

        /*
         * 多次散列:
         * 再进一步, 可以通过多次散列(对第一次的加密结果再进行加密, 可执行多次, 即参数可传2、3...), 进一步提高安全性
         */
        Md5Hash md5HashPassword3 = new Md5Hash(password, salt, 2);
        System.out.println(md5HashPassword3);

        /*
         * SimpleHash加密:
         * 第一个参数: 加密算法名称;
         * 第二个参数: 加密对象;
         * 第三个参数: 盐;
         * 第四个参数: 散列次数;
         */
        SimpleHash simpleHashPassword =
                new SimpleHash("md5", password, salt, 2);
        System.out.println(simpleHashPassword);
    }

    /**
     * 模拟用户注册, 将散列应用到Shiro认证中;
     * 相关参数:
     * (1). 用户注册---用户名: zzq, 密码: zzqgo;
     * (2). 加密参数---加密算法: MD5, 盐: feiwu, 散列次数: 2;
     */
    private static void registerTest() {
        String password = "zzqgo";
        String salt = "feiwu";

        Md5Hash md5HashPassword = new Md5Hash(password, salt, 2);
        System.out.println(md5HashPassword);

        // 保存生成的加密密码到数据库中(0f7c76eb7e2666f25aadabe11b7cd8f2)
    }

    /**
     * Shiro授权流程
     */
    private static void shiroAuthorizationTest() {
        // 用户输入
        String username = "zzq";
        String password = "zzqgo";

        // IniSecurityManagerFactory factory = new IniSecurityManagerFactory("classpath:shiro-ini.ini");
        IniSecurityManagerFactory factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);

        System.out.println("用户登录...");
        try {
            subject.login(token);
        } catch (UnknownAccountException e) {
            System.out.println("账号不存在");
            e.printStackTrace();
        } catch (IncorrectCredentialsException e) {
            System.out.println("密码错误");
            e.printStackTrace();
        }
        System.out.println("该用户是否认证成功: " + subject.isAuthenticated());

        // 授权(在认证成功之后才能去做授权)
        System.out.println("授权...");
        String role1 = "role1";
        String role2 = "role2";
        String role3 = "role3";
        String userCreate = "user:create";
        String userUpdate = "user:update";
        String userDelete = "user:delete";
        String userEdit = "user:edit";

        System.out.println("角色验证...");

        // 判断当前用户是否具备某一个角色
        System.out.println("该用户是否具备角色---role1: " + subject.hasRole(role1));
        System.out.println("该用户是否具备角色---role2: " + subject.hasRole(role2));
        System.out.println("该用户是否具备角色---role3: " + subject.hasRole(role3));

        // 判断当前用户是否同时具备多个角色
        System.out.println("该用户是否同时具备角色---role1、role2: " + subject.hasAllRoles(Arrays.asList(role1, role2)));

        System.out.println("权限验证...");

        // 判断当前用户是否具备某一个权限
        System.out.println("该用户是否具备权限---user:create: " + subject.isPermitted(userCreate));
        System.out.println("该用户是否具备权限---user:update: " + subject.isPermitted(userUpdate));
        System.out.println("该用户是否具备权限---user:delete: " + subject.isPermitted(userDelete));
        System.out.println("该用户是否具备权限---user:edit: " + subject.isPermitted(userEdit));

        // 判断当前用户是否同时具备多个权限
        System.out.println("该用户是否同时具备权限---user:create、update、delete: "
                + subject.isPermittedAll(userCreate, userUpdate, userDelete));
    }

}
