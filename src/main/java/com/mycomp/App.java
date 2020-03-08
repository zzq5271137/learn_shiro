package com.mycomp;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;

/**
 * Shiro认证(authentication), ini的形式;
 */
public class App {
    private static final String USERNAME = "zzq1";
    private static final String PASSWORD = "zzqgo1";

    public static void main(String[] args) {
        // 1. 构建SecurityManager工厂, 加载ini文件(@deprecated, 过期方法)
        IniSecurityManagerFactory factory = new IniSecurityManagerFactory("classpath:shiro.ini");

        // 2. 通过工厂创建SecurityManager
        SecurityManager securityManager = factory.getInstance();

        // 3. 将SecurityManager设置到运行环境中
        SecurityUtils.setSecurityManager(securityManager);

        // 4. 创建一个Subject实例
        Subject subject = SecurityUtils.getSubject();

        // 5. 创建token令牌(在实际应用中, token令牌应该是由文本框输入的, 如登录的用户名和密码)
        UsernamePasswordToken token = new UsernamePasswordToken(USERNAME, PASSWORD);

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
}
