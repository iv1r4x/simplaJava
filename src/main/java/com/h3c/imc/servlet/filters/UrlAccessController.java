package com.h3c.imc.servlet.filters;

import com.h3c.imc.common.AuthenticationContext;
import com.h3c.imc.plat.PlatformException;
import com.h3c.imc.plat.entity.SysParameter;
import com.h3c.imc.plat.operator.PrivilegeInit;
import com.h3c.imc.plat.operator.view.OperatorLoginInfo;
import com.h3c.imc.plat.operator.view.PrivilegeUrlManager;
import com.h3c.imc.plat.sysparameter.func.ConfigParaMgr;
import com.h3c.imc.res.memRes.func.QueryMemResMgr;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Stack;
import javax.faces.application.ViewExpiredException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.WebApplicationContext;

public class UrlAccessController
        implements Filter
{
    public static final Log log = LogFactory.getLog(UrlAccessController.class);
    public static final String SERVLET_CONTEXT_ATTR_NAME = UrlAccessController.class.getName() + "_urlAccessController";
    public static final String SESSION_LASTACCESS_ATTR_NAME = UrlAccessController.class.getName() + "_LastAccess";
    private static final String ESCAPE_OF_ACCESS_CONTROL_URL_PREFIX = UrlAccessController.class.getPackage().getName() + ".ESCAPE_OF_ACCESS_CONTROL_URL";
    private static final String AUTOREFRESH_ACCESS_CONTROL_URL_PREFIX = UrlAccessController.class.getPackage().getName() + ".AUTOREFRESH_ACCESS_CONTROL_URL";
    private static final String VIEW_EXPIRE_REDIRECT_PAGE = UrlAccessController.class.getPackage().getName() + ".VIEW_EXPIRE_REDIRECT_PAGE";
    private ServletContext context;
    public static final String NOCHECK_PREFIX = "{$NOCHECK}";
    private long sessionTimeout;

    public void setSessionTimeout(long sessionTimeout)
    {
        this.sessionTimeout = sessionTimeout;
    }

    private String[] escapedUrls = null;
    private String[] autoRefreshUrls = null;
    private String viewExpireRedirectPage = "/imc/navigationToLogin.xhtml";

    public static UrlAccessController getCurrentInstance(ServletContext sc)
    {
        return (UrlAccessController)sc.getAttribute(SERVLET_CONTEXT_ATTR_NAME);
    }

    public void fireLastAccessEvent(HttpSession session)
    {
        try
        {
            session.setAttribute(SESSION_LASTACCESS_ATTR_NAME, Long.valueOf(System.currentTimeMillis()));
            if (log.isDebugEnabled()) {
                log.debug("Fire last access event on session: " + session.getId());
            }
        }
        catch (IllegalStateException ise)
        {
            log.warn("Session is invalidated", ise);
        }
    }

    public boolean isSessionTimeout(HttpSession session)
    {
        long currentTime = System.currentTimeMillis();

        Long lastAccessTime = (Long)session.getAttribute(SESSION_LASTACCESS_ATTR_NAME);
        if (lastAccessTime == null)
        {
            session.setAttribute(SESSION_LASTACCESS_ATTR_NAME, Long.valueOf(currentTime));
            return false;
        }
        return (currentTime - lastAccessTime.longValue()) / 1000L > session.getMaxInactiveInterval();
    }

    public void init(FilterConfig filterConfig)
            throws ServletException
    {
        long startTime = System.currentTimeMillis();

        context = filterConfig.getServletContext();

        context.setAttribute(SERVLET_CONTEXT_ATTR_NAME, this);

        Set<String> escapedSet = new HashSet();
        Set<String> autoRefreshSet = new HashSet();
        Enumeration<?> e = context.getInitParameterNames();
        while (e.hasMoreElements())
        {
            String name = (String)e.nextElement();
            if (name.startsWith(ESCAPE_OF_ACCESS_CONTROL_URL_PREFIX))
            {
                String value = context.getInitParameter(name);
                if (value != null)
                {
                    value = value.trim();
                    escapedSet.add(value);
                    context.log("Add escape of access control URL: " + value);
                }
            }
            else if (name.startsWith(AUTOREFRESH_ACCESS_CONTROL_URL_PREFIX))
            {
                String value = context.getInitParameter(name);
                if (value != null)
                {
                    value = value.trim();
                    autoRefreshSet.add(value);
                    context.log("Add auto-refresh access control URL: " + value);
                }
            }
            else if (VIEW_EXPIRE_REDIRECT_PAGE.equals(name))
            {
                viewExpireRedirectPage = context.getInitParameter(VIEW_EXPIRE_REDIRECT_PAGE);
            }
        }
        escapedUrls = ((String[])escapedSet.toArray(new String[0]));
        autoRefreshUrls = ((String[])autoRefreshSet.toArray(new String[0]));

        WebApplicationContext wac = (WebApplicationContext)context.getAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE);

        ConfigParaMgr mgr = (ConfigParaMgr)wac.getBean("platConfigParaMgr");
        sessionTimeout = (Long.parseLong(mgr.queryConfigParaByName("timeout").getValue()) * 60L * 1000L);

        context.log("Initial session timeout value: " + sessionTimeout + " ms");
        long endTime = System.currentTimeMillis();
        log.debug("UrlAccessController init waste : " + (endTime - startTime) + " ms.");
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException
    {
        if ((!(request instanceof HttpServletRequest)) || (!(response instanceof HttpServletResponse)))
        {
            chain.doFilter(request, response);
            return;
        }
        HttpServletRequest req = (HttpServletRequest)request;
        HttpServletResponse resp = (HttpServletResponse)response;

        HttpSession session = req.getSession();

        String uri = normalizeSyntax(req.getRequestURI());

        WebApplicationContext wac = (WebApplicationContext)context.getAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE);

        ApplicationContext ac = wac.getParent();
        QueryMemResMgr resQueryMgr = (QueryMemResMgr)ac.getBean("resQueryMemResMgr");
        String customLoginPageMapURL = resQueryMgr.getCustomLoginPageMapURL();
        if (StringUtils.startsWith(uri, "/imc/primepush/"))
        {
            chain.doFilter(request, response);
            return;
        }
        log.debug("uri is : " + uri);
        if (("GET".equals(req.getMethod())) && (req.getParameter("refresh") != null)) {
            uri = uri + "?refresh=" + req.getParameter("refresh");
        }
        String query = req.getQueryString();
        if (query != null)
        {
            String q = query.toLowerCase();
            boolean attack = false;

            int start = 0;
            int idx = q.indexOf('<', start);
            while ((idx > 0) && (q.length() > idx + 1))
            {
                char c = q.charAt(idx + 1);
                if ((c == '%') || (c == '/') || ((c > '`') && (c < '{')))
                {
                    attack = true;
                    query = query.substring(0, idx) + "&lt;" + query.substring(idx + 1);
                    q = q.substring(0, idx) + "&lt;" + q.substring(idx + 1);
                    start = idx + 4;
                }
                else
                {
                    start = idx + 1;
                }
                idx = q.indexOf('<', start);
            }
            start = 0;
            idx = q.indexOf("%3c", start);
            while ((idx > 0) && (q.length() > idx + 3))
            {
                char c = q.charAt(idx + 3);
                if ((c == '%') || (c == '/') || ((c > '`') && (c < '{')))
                {
                    attack = true;
                    query = query.substring(0, idx) + "&lt;" + query.substring(idx + 3);
                    q = q.substring(0, idx) + "&lt;" + q.substring(idx + 3);
                    start = idx + 4;
                }
                else
                {
                    start = idx + 3;
                }
                idx = q.indexOf("%3c", start);
            }
            if (uri.contains("addFavourite")) {
                attack = false;
            }
            if (attack)
            {
                String url = uri + "?" + req.getQueryString();
                String nurl = uri + "?" + query;
                log.warn("XSS Attach detected, URI=" + url + ", IP=" + req.getRemoteAddr() + ", redirect to: " + nurl);

                resp.sendRedirect(nurl);
                return;
            }
        }
        String u = uri.toLowerCase();
        if (u.contains(";jsessionid")) {
            u = StringUtils.substringBeforeLast(u, ";jsessionid");
        }
        if ((u.endsWith(".gif")) || (u.endsWith(".png")) || (u.endsWith(".css")) || (u.endsWith(".js")) || (u.endsWith(".jpg")) || (u.endsWith(".jpeg")) || (u.endsWith("bmp")) || (u.indexOf("/platflexmessagebroker/") != -1) || (u.endsWith(".jar")) || (u.endsWith(".class")) || (u.endsWith(".jnlp")) || (u.endsWith(".wav")))
        {
            chain.doFilter(req, resp);
            return;
        }
        OperatorLoginInfo currOperatorLoginInfo = null;
        try
        {
            currOperatorLoginInfo = OperatorLoginInfo.getLoginOperator(session);
        }
        catch (PlatformException pe)
        {
            log.warn("Access URL With No OperatorInfo: " + uri + "?" + req.getQueryString() + " from " + req.getRemoteAddr());
        }
        if (currOperatorLoginInfo != null)
        {
            long time = currOperatorLoginInfo.getTimeForLicenseNumberCheckFail();
            if (time > 0L)
            {
                Date date = new Date();
                long currTime = date.getTime();
                if (currTime >= time)
                {
                    log.debug("license check fail time reached, currTime : " + currTime + ";logoutTime : " + time);

                    redirectLoginPage(req.getContextPath(), req, resp);
                    try
                    {
                        session.invalidate();
                    }
                    catch (Exception e)
                    {
                        log.debug("invalidate session", e);
                    }
                    return;
                }
            }
        }
        String contextPath = req.getContextPath();

        uri = checkUriWithSpecialChar(uri);

        String suburi = uri.substring(contextPath.length());

        Locale currLocale = Locale.getDefault();
        PrivilegeInit pInit = getPrivilegeInit();
        if (pInit != null)
        {
            Locale oldLocale = pInit.getLocale();
            if ((oldLocale != null) && (!oldLocale.equals(currLocale)))
            {
                log.info("current locale is : " + currLocale + ", init locale is : " + oldLocale + ", need to change.");
                Locale.setDefault(oldLocale);
            }
        }
        if (!suburi.startsWith("/loginCmdForAgent.js")) {
            resp.setHeader("P3P", "CP=CAO PSA OUR");
        }
        if ((suburi.endsWith(".js.jsf")) || (suburi.endsWith(".gif.jsf")) || (suburi.equals("")) || (suburi.equals("/")) || (suburi.startsWith("/default.js")) || (suburi.startsWith("/default.xhtml")) || (suburi.startsWith("/copyright.js")) || (suburi.startsWith("/copyright.xhtml")) || (suburi.startsWith("/errorpage.js")) || (suburi.startsWith("/errorpage.xhtml")) || (suburi.startsWith("/download.js")) || (suburi.startsWith("/download.xhtml")) || (suburi.startsWith("/index.js")) || (suburi.startsWith("/index.xhtml")) || (suburi.startsWith("/login.js")) || (suburi.startsWith("/login.xhtml")) || (suburi.startsWith("/loginCmd.js")) || (suburi.startsWith("/loginCmd.xhtml")) || (suburi.startsWith("/loginCmdForAgent.js")) || (suburi.startsWith("/loginCmdForAgent.xhtml")) || (suburi.startsWith("/loginForAgent.js")) || (suburi.startsWith("/loginForAgent.xhtml")) || (suburi.startsWith("/loginSuccess.js")) || (suburi.startsWith("/loginSuccess.xhtml")) || (suburi.startsWith("/navigationToImc.js")) || (suburi.startsWith("/navigationToImc.xhtml")) || (suburi.startsWith("/navigationToImcWithParam.js")) || (suburi.startsWith("/navigationToImcWithParam.xhtml")) || (suburi.startsWith("/result.js")) || (suburi.startsWith("/result.xhtml")) || (suburi.startsWith("/set.js")) || (suburi.startsWith("/set.xhtml")) || (suburi.startsWith("/test.js")) || (suburi.startsWith("/test.xhtml")) || (suburi.startsWith("/noAccessPermission.js")) || (suburi.startsWith("/noAccessPermission.xhtml")) || (suburi.startsWith("/relogin.js")) || (suburi.startsWith("/relogin.xhtml")) || (suburi.startsWith("/reloginFromLogout.js")) || (suburi.startsWith("/reloginFromLogout.xhtml")) || (suburi.startsWith("/navigationToLogin.js")) || (suburi.startsWith("/navigationToLogin.xhtml")) || (suburi.startsWith("/images/")) || (suburi.startsWith("/inc/")) || (suburi.startsWith("/javax.faces.resource/")) || (suburi.startsWith("/jscript/")) || (suburi.startsWith("/services")) || (suburi.startsWith("/index/images/")) || (suburi.startsWith("/license/")) || (suburi.startsWith("/topo/closeTopo.js")) || (suburi.startsWith("/topo/closeTopo.xhtml")) || (suburi.startsWith("/topo/reloginFromTopo.js")) || (suburi.startsWith("/topo/reloginFromTopo.xhtml")) || (suburi.startsWith("/test/")) || (suburi.startsWith("/a4j")) || (suburi.startsWith("/terms.html")) || (suburi.startsWith("/adf/jsLibs/")) || (suburi.startsWith("/tmp/")) || (suburi.startsWith("/noAuth/")) || (suburi.startsWith("/topo/")) || (suburi.indexOf("twaver") != -1) || (suburi.startsWith("/topo/style/defaultstyle/locale/")) || (suburi.startsWith("/fault/accessMgrServlet")) || (suburi.startsWith("/fault/applet/faultBoardChart_content.xhtml")) || (suburi.startsWith("/mobile/login.xhtml")) || (suburi.startsWith("/mobile/login.jsf")) || ((null != customLoginPageMapURL) && (customLoginPageMapURL.length() > 0) && (suburi.equals(customLoginPageMapURL))))
        {
            try
            {
                log.debug("execute do filter.");
                chain.doFilter(request, response);
            }
            catch (ServletException se)
            {
                log.debug("abbbbc" + suburi);
                if ((se.getCause() instanceof ViewExpiredException)) {
                    redirect(req, resp);
                } else {
                    throw se;
                }
            }
            return;
        }
        for (String autoRefreshUrl : autoRefreshUrls) {
            if (suburi.startsWith(autoRefreshUrl))
            {
                if (log.isDebugEnabled()) {
                    log.debug("AutoRefresh URL access control: " + suburi);
                }
                try
                {
                    try
                    {
                        currOperatorLoginInfo = OperatorLoginInfo.getLoginOperator(session);
                    }
                    catch (PlatformException pe)
                    {
                        log.warn("Access URL With No OperatorInfo for escape URL : " + uri + "?" + req.getQueryString() + " from " + req.getRemoteAddr());

                        redirectLoginPage(contextPath, req, resp);
                        return;
                    }
                    chain.doFilter(request, response);
                }
                catch (ServletException se)
                {
                    if ((se.getCause() instanceof ViewExpiredException))
                    {
                        redirect(req, resp);
                    }
                    else
                    {
                        if ((se.getCause() instanceof PlatformException))
                        {
                            if (50324 == ((PlatformException)se.getCause()).getErrorCode())
                            {
                                log.debug("operation is no online. " + suburi);
                                redirectLoginPage(contextPath, req, resp);
                                return;
                            }
                            throw se;
                        }
                        throw se;
                    }
                }
                return;
            }
        }
        for (String escapeUrl : escapedUrls) {
            if (suburi.startsWith(escapeUrl))
            {
                if (log.isDebugEnabled()) {
                    log.debug("Escape URL access control: " + suburi);
                }
                try
                {
                    chain.doFilter(request, response);
                }
                catch (ServletException se)
                {
                    if ((se.getCause() instanceof ViewExpiredException))
                    {
                        redirect(req, resp);
                    }
                    else
                    {
                        if ((se.getCause() instanceof PlatformException))
                        {
                            if (50324 == ((PlatformException)se.getCause()).getErrorCode())
                            {
                                log.debug("operation is no online. " + suburi);
                                redirectLoginPage(contextPath, req, resp);
                                return;
                            }
                            throw se;
                        }
                        throw se;
                    }
                }
                return;
            }
        }
        List<PrivilegeUrlManager> privilegeUrlManagerList = getPrivilegeUrlManager(context);
        if ((privilegeUrlManagerList != null) && (privilegeUrlManagerList.size() > 0)) {
            for (PrivilegeUrlManager p : privilegeUrlManagerList)
            {
                Map<String, List<String>> map = p.getNoCheckUrlMap();
                if ((map != null) && (map.size() > 0))
                {
                    Set<Map.Entry<String, List<String>>> entrySet = map.entrySet();
                    for (Map.Entry<String, List<String>> entry : entrySet)
                    {
                        String key = (String)entry.getKey();
                        List<String> valueList = (List)entry.getValue();
                        if ((StringUtils.startsWithIgnoreCase(key, "{$NOCHECK}")) &&
                                (valueList != null) && (valueList.size() > 0)) {
                            for (String value : valueList) {
                                if (suburi.startsWith(value))
                                {
                                    try
                                    {
                                        chain.doFilter(request, response);
                                    }
                                    catch (ServletException se)
                                    {
                                        if ((se.getCause() instanceof ViewExpiredException)) {
                                            redirect(req, resp);
                                        } else {
                                            throw se;
                                        }
                                    }
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        }
        OperatorLoginInfo operator = null;
        try
        {
            operator = OperatorLoginInfo.getLoginOperator(session);
        }
        catch (PlatformException pe)
        {
            log.warn("Access URL With No OperatorInfo: " + uri + "?" + req.getQueryString() + " from " + req.getRemoteAddr());
        }
        if ((operator == null) || (isSessionInvalidated(session, suburi)))
        {
            if (suburi.endsWith(".gwtsvc")) {
                resp.sendError(417, "NOT_LOGIN");
            } else {
                redirectLoginPage(contextPath, req, resp);
            }
            log.info("aaa:" + uri);
            return;
        }
        for (PrivilegeUrlManager privilegeUrlManager : privilegeUrlManagerList) {
            if ((privilegeUrlManager != null) && (operator != null))
            {
                if (!privilegeUrlManager.isUrlAllowed(suburi, operator)) {
                    resp.sendRedirect(contextPath + "/noAccessPermission.jsf");
                }
            }
            else
            {
                redirectLoginPage(contextPath, req, resp);
                return;
            }
        }
        PrivilegeInit privilegeInit = getPrivilegeInit();
        if ((privilegeInit != null) && (operator != null))
        {
            if (!privilegeInit.isUrlAllowed(suburi, operator.getPrivileges())) {
                resp.sendRedirect(contextPath + "/noAccessPermission.jsf");
            }
        }
        else
        {
            redirectLoginPage(contextPath, req, resp);
            return;
        }
        try
        {
            AuthenticationContext.setAuthenticatedUser(operator.getLoginName());
            chain.doFilter(request, response);
        }
        catch (ServletException se)
        {
            if ((se.getCause() instanceof ViewExpiredException)) {
                redirect(req, resp);
            } else {
                throw se;
            }
        }
        finally
        {
            AuthenticationContext.setAuthenticatedUser(null);
        }
    }

    private String xmlPartialRedirectToPage(HttpServletRequest request, String page)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("<?xml version='1.0' encoding='UTF-8'?>");
        sb.append("<partial-response><redirect url=\"").append(request.getContextPath()).append(request.getServletPath()).append(page).append("\"/></partial-response>");
        return sb.toString();
    }

    private boolean isAjax(HttpServletRequest request)
    {
        return "XMLHttpRequest".equals(request.getHeader("X-Requested-With"));
    }

    private void redirectLoginPage(String contextPath, HttpServletRequest req, HttpServletResponse resp)
            throws IOException
    {
        log.debug("abbbdddd" + contextPath);
        if (!isAjax(req))
        {
            String redirectPage = "/navigationToLogin.xhtml?reloginFlag=true";

            Cookie[] cookies = req.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies)
                {
                    String cn = cookie.getName();
                    String cv = cookie.getValue();
                    if ("homeLoginPage".equals(cn))
                    {
                        redirectPage = cv;
                        log.info("search all cookies and find homeLoginPage : " + cv);

                        cookie.setMaxAge(0);
                        resp.addCookie(cookie);
                    }
                }
            }
            try
            {
                if ((!StringUtils.startsWith(redirectPage, "http://")) && (!StringUtils.startsWith(redirectPage, "https://"))) {
                    redirectPage = contextPath + redirectPage;
                }
                resp.sendRedirect(redirectPage);
            }
            catch (Throwable t)
            {
                log.warn(null, t);
            }
        }
        else
        {
            log.warn("Session expiration during ajax request, partial redirect to login page");
            HttpServletResponse response = resp;
            response.getWriter().print(xmlPartialRedirectToPage(req, "/navigationToLogin.xhtml?session_expired=1"));
            response.flushBuffer();
        }
    }

    private void redirect(HttpServletRequest req, HttpServletResponse resp)
            throws IOException
    {
        String uri = req.getRequestURI();
        String page = viewExpireRedirectPage == null ? uri : viewExpireRedirectPage;
        log.warn("View state expired, uri=" + uri + ", clientIp=" + req.getRemoteAddr() + ", redirect to " + page);

        resp.sendRedirect(page);
    }

    private PrivilegeInit getPrivilegeInit()
    {
        WebApplicationContext wac = (WebApplicationContext)context.getAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE);

        ApplicationContext ac = wac.getParent();
        if (ac.containsBean("privilegeInit")) {
            return (PrivilegeInit)ac.getBean("privilegeInit");
        }
        return null;
    }

    public void destroy()
    {
        context.removeAttribute(SERVLET_CONTEXT_ATTR_NAME);

        escapedUrls = null;
        autoRefreshUrls = null;
    }

    private List<PrivilegeUrlManager> getPrivilegeUrlManager(ServletContext sc)
    {
        return PrivilegeUrlManager.getPrivilegeUrlManager(sc);
    }

    private boolean isSessionInvalidated(HttpSession session, String uri)
    {
        long currentTime = System.currentTimeMillis();

        Long lastAccessTime = (Long)session.getAttribute(SESSION_LASTACCESS_ATTR_NAME);
        if (lastAccessTime == null)
        {
            session.setAttribute(SESSION_LASTACCESS_ATTR_NAME, Long.valueOf(currentTime));
            return false;
        }
        if ((currentTime - lastAccessTime.longValue()) / 1000L > session.getMaxInactiveInterval())
        {
            session.invalidate();
            return true;
        }
        boolean escaped = false;
        for (String eu : escapedUrls) {
            if (uri.startsWith(eu))
            {
                escaped = true;
                break;
            }
        }
        for (String ar : autoRefreshUrls) {
            if (uri.startsWith(ar))
            {
                escaped = true;
                break;
            }
        }
        if (!escaped) {
            session.setAttribute(SESSION_LASTACCESS_ATTR_NAME, Long.valueOf(currentTime));
        }
        return false;
    }

    private String checkUriWithSpecialChar(String originUri)
    {
        if (originUri != null)
        {
            originUri = StringUtils.replaceChars(originUri, "\\", "/");
            if (originUri.contains("/"))
            {
                String[] uriArray = StringUtils.split(originUri, "/");
                String newStr = "";
                if (uriArray.length > 0) {
                    for (int i = 0; i < uriArray.length; i++) {
                        newStr = newStr.concat("/").concat(StringUtils.replaceChars(uriArray[i], "/", ""));
                    }
                }
                originUri = newStr;
            }
        }
        return originUri;
    }

    public static void main(String[] args)
    {
        UrlAccessController con = new UrlAccessController();
        String uri = "////\\\\imc////\\\\\\loginSuccess.jsf";
        uri = con.checkUriWithSpecialChar(uri);
        System.out.println("uri is : " + uri);
    }

    private static URI normalizeSyntax(URI uri)
    {
        if (uri.isOpaque()) {
            return uri;
        }
        String path = uri.getPath() == null ? "" : uri.getPath();
        String[] inputSegments = path.split("/");
        Stack<String> outputSegments = new Stack();
        for (String inputSegment : inputSegments) {
            if ((inputSegment.length() != 0) && (!".".equals(inputSegment))) {
                if (("..".equals(inputSegment)) || (StringUtils.equalsIgnoreCase("%2e%2e", inputSegment)))
                {
                    if (!outputSegments.isEmpty()) {
                        outputSegments.pop();
                    }
                }
                else {
                    outputSegments.push(inputSegment);
                }
            }
        }
        StringBuilder outputBuffer = new StringBuilder();
        for (String outputSegment : outputSegments) {
            outputBuffer.append('/').append(outputSegment);
        }
        if (path.lastIndexOf('/') == path.length() - 1) {
            outputBuffer.append('/');
        }
        try
        {
            String scheme = uri.getScheme().toLowerCase();
            String auth = uri.getAuthority().toLowerCase();
            URI ref = new URI(scheme, auth, outputBuffer.toString(), null, null);
            if ((uri.getQuery() == null) && (uri.getFragment() == null)) {
                return ref;
            }
            StringBuilder normalized = new StringBuilder(ref.toASCIIString());
            if (uri.getQuery() != null) {
                normalized.append('?').append(uri.getRawQuery());
            }
            if (uri.getFragment() != null) {
                normalized.append('#').append(uri.getRawFragment());
            }
            return URI.create(normalized.toString());
        }
        catch (URISyntaxException e)
        {
            throw new IllegalArgumentException(e);
        }
    }

    private static String normalizeSyntax(String path)
    {
        if ((!StringUtils.contains(path, "..")) && (!StringUtils.containsIgnoreCase(path, "..")) && (!StringUtils.containsIgnoreCase(path, "%2e%2e"))) {
            return path;
        }
        String[] inputSegments = path.split("/");
        Stack<String> outputSegments = new Stack();
        for (String inputSegment : inputSegments) {
            if ((inputSegment.length() != 0) && (!".".equals(inputSegment))) {
                if (("..".equals(inputSegment)) || (StringUtils.equalsIgnoreCase("%2e%2e", inputSegment)))
                {
                    if (!outputSegments.isEmpty()) {
                        outputSegments.pop();
                    }
                }
                else {
                    outputSegments.push(inputSegment);
                }
            }
        }
        StringBuilder outputBuffer = new StringBuilder();
        for (String outputSegment : outputSegments) {
            outputBuffer.append('/').append(outputSegment);
        }
        if (path.lastIndexOf('/') == path.length() - 1) {
            outputBuffer.append('/');
        }
        return outputBuffer.toString();
    }
}

/* Location:
 * Qualified Name:     com.h3c.imc.servlet.filters.UrlAccessController
 * Java Class Version: 7 (51.0)
 * JD-Core Version:    0.7.1
 */