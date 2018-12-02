package WsModelLib;

import CommonLib.Common;
import CommonLib.Crypto.AES;
import CommonModelLib.dbModel.IEnumCache;
import CommonModelLib.objectModel.users.AuthUserInfo;
import DBmethodsLib.DBmethodsCommon;
import DBmethodsLib.DBmethodsOra;
import DBmethodsLib.DBmethodsPostgres;
import WSCommonLib.SecurityHeaderType;
import WSCommonLib.UsernameTokenType;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Objects;
import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;
import org.postgresql.util.PSQLException;
import org.postgresql.util.ServerErrorMessage;

/**
 *
 * 
 * @param <AUI>
 */
public abstract class WsModel<AUI extends AuthUserInfo>
{
    protected static int tempLockTimeout_sec = 15;
    protected final String serviceName;
    final String jarFileName;
    protected final String system_alias;
    final Common.Log settingsFAILlog;
    final String initParameterName_DB_URL;
    final String initParameterName_DB_USER;
    final String initParameterName_DB_PASS;
    public WsModel(String serviceName, String jarFileName, String system_alias, String initParameterName_DB_URL, String initParameterName_DB_USER, String initParameterName_DB_PASS)
    {
        this.serviceName = serviceName;
        this.jarFileName = jarFileName;
        this.system_alias = system_alias;
        this.settingsFAILlog = new Common.Log(true, jarFileName + ".settingsFAILlog", true, Common.SlashOnEnd(System.getProperty("user.home")) +  Common.ReplaceBadPathChars(serviceName, "") + "__settingsFAILlog");
        this.initParameterName_DB_URL = initParameterName_DB_URL;
        this.initParameterName_DB_USER = initParameterName_DB_USER;
        this.initParameterName_DB_PASS = initParameterName_DB_PASS;
    }
    Integer system_en;
    protected int getSystem_en()
    {
        if (system_en == null)
            try {
                system_en = (Integer)getDbmethods().select_from(true, "select " + IEnumCache.enum_idSQL(system_alias))[0].Rows.get(0).get(0);
            } catch (RetryException | SQLException ex) {
                throw new RuntimeException(ex);
            }
        return system_en;
    }
    
    //@Resource volatile WebServiceContext wsContext;
    protected abstract WebServiceContext webServiceContext();
    protected String getRemoteAddr(boolean includeErrMessage)
    {
        try
        {
            MessageContext mc = webServiceContext().getMessageContext();                        
            Object req = mc.get(MessageContext.SERVLET_REQUEST);//HttpServletRequest
            return req.getClass().getMethod("getRemoteAddr", (Class<?>[])null).invoke(req, (Object[])null).toString();//return req.getRemoteAddr(); 
        }
        catch (Exception ex)
        {
            return "-.-.-.-" + (includeErrMessage ? "(" + Common.nz(ex.getMessage()) + ")" : "");
        }
    }    
    
    public static class RetryException extends Exception {
        public RetryException(String Message) {
            super(Message);
        }
    }
    
    protected InitParameters getInitParameters() throws RetryException
    {
        if (initParameters == null)            
            initParameters = new InitParameters(webServiceContext(), new String[] { initParameterName_DB_URL, initParameterName_DB_USER, initParameterName_DB_PASS });
        return initParameters;
    }
    protected volatile InitParameters initParameters;
    protected static class InitParameters
    {
        final String initParameterName_logs_path = "logs_path";
        Object sc;//ServletContext
        HashMap<String, String> hm;
        public InitParameters(WebServiceContext wsc, String[] requiredInitParameters) throws RetryException
        {                    
            try
            {
                sc = wsc.getMessageContext().get(MessageContext.SERVLET_CONTEXT);
            }
            catch(Exception ex)
            {
                throw new RetryException("SERVLET_CONTEXT not initialized yet. Please retry.");
            }
            if (sc == null)
                throw new RetryException("SERVLET_CONTEXT == null. Please retry.");
            hm = new HashMap<>();
            get(initParameterName_logs_path);
            for (String k : requiredInitParameters)
                get(k);
        }
        public final String get(String k)
        {
            if (!hm.containsKey(k))
            {
                Object v;
                try {       
                    v = sc.getClass().getMethod("getInitParameter", String.class).invoke(sc, k);
                } catch (Exception ex) {
                    throw new RuntimeException(Common.throwableToString(ex, Common.getCurrentSTE()));
                }
                if (v == null)
                    throw new NoSuchInitParameterException(k);
                hm.put(k, v.toString());//hm.put(k, sc.get(k));
            }            
            return hm.get(k);
        }
        public final String getNullable(String k)
        {
            try {       
                return get(k);
            } catch (NoSuchInitParameterException ex) {
                return null;
            }            
        }
        public String logs_path()   { return get(initParameterName_logs_path); }
    }
    public static class NoSuchInitParameterException extends RuntimeException { public NoSuchInitParameterException(String message) { super(message); } }
    
    
    
    
    protected abstract char[] dedk();
    volatile DBmethodsCommon dbmethods;
    protected final Object dbmethodsIOLOCK = new Object();
    final protected DBmethodsCommon getDbmethods() throws RetryException
    {
        if (dbmethods == null)
        {
            synchronized(dbmethodsIOLOCK)
            {
                if (dbmethods == null)
                {                
                    String PASS = getInitParameters().get(initParameterName_DB_PASS);
                    try
                    {
                        PASS = AES.decrypt(PASS, new String(dedk()));
                    }
                    catch(Exception ex) { }
                    String URL = getInitParameters().get(initParameterName_DB_URL);
                    String USER = getInitParameters().get(initParameterName_DB_USER);
                    if (URL.toLowerCase().startsWith("jdbc:oracle:"))
                    {
                        dbmethods = new DBmethodsOra(URL, USER, PASS);
                    }
                    else if (URL.toLowerCase().startsWith("jdbc:postgresql:"))
                    {
                        dbmethods = new DBmethodsPostgres(URL, USER, PASS, 0);
                    }
                    else
                        throw new Error("MUSTNEVERTHROW: " + initParameterName_DB_URL + " must be either jdbc:oracle , or jdbc:postgresql!");
                }
            }
        }
        return dbmethods;
    }
    
    
    
    
    
    
    Boolean isDebug;
    protected boolean IsDebug()
    {
        if (initParameters != null)
        {
            if (isDebug == null)
                try
                {
                    String v = initParameters.get("IsDebug");
                    isDebug = v == null ? false : v.toLowerCase().equals("true");
                }
                catch(Exception ex)
                {
                    return false;
                }
            return isDebug;
        }            
        return false;
    }
    
    
    
    
    
    
    
    
        
    volatile boolean postConstructWasCalled = false;
    final Object postConstructLOCK = new Object();
    //@PostConstruct
    protected final void postConstruct()
    {
        if (initParameters == null)
        {
            synchronized(postConstructLOCK)
            { 
                if (initParameters == null)
                {
                    if (!postConstructWasCalled)
                    {
                        postConstructWasCalled = true;
                        try { Thread.sleep(50); } catch (InterruptedException iex) {throw new RuntimeException(iex);}            
                    }
                    else
                        for(int n = 0; n < 200 && initParameters == null; n++)
                        {
                            try { Thread.sleep(100); } catch (InterruptedException iex) {throw new RuntimeException(iex);}            
                        }
                }
            }
        }
    }  
    
    
    
    
    
    
    
    
            
    volatile boolean inited = false;
    final Object initOnceLOCK = new Object();
    final protected void initOnce() throws RetryException
    {
        if (!inited)
        {
            synchronized(initOnceLOCK)
            {
                if (!inited)
                {
                    getInitParameters();
                    
                    String v = initParameters.getNullable("maxBadPasswords_timeoutSeconds");
                    if (v != null)
                        WSCommonLib.UsernameTokenType.maxBadPasswords_timeoutSeconds = Integer.parseInt(v);
    
                    initOnce_add();
                    
                    Common.debugLog = customLog("debug");

                    inited = true;
                }
            }
        }
    }
    protected abstract void initOnce_add() throws RetryException;
    
    
    
    
    
    
    
    
    Common.Log SpecifiedExceptionsLog_;
    Common.Log ERRORSLog_;
    protected Common.Log SpecifiedExceptionsLog()
    {
        if (SpecifiedExceptionsLog_==null)
        {
            if (initParameters==null)
                return settingsFAILlog;
            SpecifiedExceptionsLog_ = new Common.Log(true, serviceName + "_SpecifiedExceptions", true, initParameters.logs_path());
        }
        return SpecifiedExceptionsLog_;
    }
    protected Common.Log ERRORSLog()
    {
        if (ERRORSLog_==null)
        {
            if (initParameters==null)
                return settingsFAILlog;
            ERRORSLog_ = new Common.Log(true, serviceName + "_ERRORS", true, initParameters.logs_path());
        }
        return ERRORSLog_; 
    }
    HashMap<String, Common.Log> customLogs = new HashMap<>();
    final Object customLogsLOCK = new Object();
    protected Common.Log customLog(String customName)
    {
        if (!customLogs.containsKey(customName.toLowerCase()))
        {
            if (initParameters==null)
                return settingsFAILlog;
            synchronized(customLogsLOCK)
            {
                if (!customLogs.containsKey(customName.toLowerCase()))
                    customLogs.put(customName.toLowerCase(), new Common.Log(true, serviceName + "_" + Common.ReplaceBadPathChars(customName.toLowerCase(), ""), true, initParameters.logs_path()));
            }
        }
        return customLogs.get(customName.toLowerCase());
    }
    
    
    
    
    
    protected abstract AUI getAuthUserInfo(String searchlogin);
    
    public void authUser(Common.Container<AUI> resultContainer, UsernameTokenType usernameToken) throws UsernameTokenType.PasswordValidationException, RetryException
    {
        authUser(resultContainer, usernameToken, ERRORSLog(), this::getAuthUserInfo);
    }    
    public static <T extends AuthUserInfo> void authUser(Common.Container<T> resultContainer, UsernameTokenType usernameToken, Common.Log errLog, Common.Func1<String, T> getAuthUserInfo) throws UsernameTokenType.PasswordValidationException, RetryException
    {
        String nl = Common.NewLine();
        String internalDetails = (usernameToken == null ? "usernameToken == null" : 
                               "usernameToken.username: " + usernameToken.username
                        + nl + "usernameToken.password: " + usernameToken.password
                        + nl + "usernameToken.nonce: " + usernameToken.nonce
                        + nl + "usernameToken.created: " + usernameToken.created
                    );
        try
        {   
            String badUorP = "Неизвестный пользователь или пароль";
            if (usernameToken == null || usernameToken.username == null ||  usernameToken.username.isEmpty() 
                    || usernameToken.password == null || usernameToken.password.isEmpty()
                    || usernameToken.nonce == null || usernameToken.nonce.isEmpty()
                    || usernameToken.created == null || usernameToken.created.isEmpty())
                throw new UsernameTokenType.PasswordValidationException(badUorP + "!", internalDetails);

            resultContainer.value = getAuthUserInfo.call(usernameToken.username);
            if (resultContainer.value == null)
                throw new UsernameTokenType.PasswordValidationException(badUorP + ".", internalDetails + nl + "aui == null");
            
            if (resultContainer.value.user_pass == null && resultContainer.value.user_pass.length != 20)
                throw new UsernameTokenType.PasswordValidationException("неприемлемый пользователь для обмена сообщениями!!", internalDetails);// не SHA1
            String PASS = Common.bytesToHex(resultContainer.value.user_pass);
            
            if (!usernameToken.checkPwd(PASS) && !usernameToken.checkPwd(PASS.toLowerCase()))
                throw new UsernameTokenType.PasswordValidationException(badUorP, internalDetails + nl + "PASS: " + PASS + nl + "!usernameToken.checkPwd(PASS)");
            if (!resultContainer.value.isAllowedForCurrentSystem())
                throw new UsernameTokenType.PasswordValidationException("неприемлемый пользователь для обмена сообщениями!", internalDetails);//в usertosystem нет разрешения на данную систем_ен
            if (resultContainer.value.lastTempLockIdTS > 0 && Common.lapsed_sec(resultContainer.value.lastTempLockIdTS) < tempLockTimeout_sec 
                    && !Objects.equals(resultContainer.value.lastTempLockId, usernameToken.tempLockId))
                throw new UsernameTokenType.PasswordValidationException("по пользователю обнаружена попытка параллельной работы двух файловых адаптеров/клиентов веб-сервиса!", 
                        internalDetails + nl + "usernameToken.tempLockId: " + usernameToken.tempLockId + nl + "resultContainer.value.lastTempLockId: " + resultContainer.value.lastTempLockId);
            resultContainer.value.lastTempLockIdTS = System.currentTimeMillis();
            resultContainer.value.lastTempLockId = usernameToken.tempLockId;
        }
        catch(UsernameTokenType.PasswordValidationException ex)
        {
            throw new UsernameTokenType.PasswordValidationException("Ошибка проверки пользователя и пароля: " + ex.getMessage(), ex.internalDetails == null ? internalDetails : ex.internalDetails);
        } 
        catch (UsernameTokenType.RetryAuthenticationException ex) 
        {
            throw new RetryException(ex.getMessage());
        }
    }
    
    
    @WebMethod(operationName = "Unlock") @XmlElement(required = true)
    public void Unlock(
        @WebParam(name = "Security", targetNamespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", header = true)  SecurityHeaderType Security
    ) throws UsernameTokenType.PasswordValidationException, OthersException, RetryException 
    {        
        authAndDo(Security, null, 
            (aui) -> 
            {
                aui.lastTempLockId = null;
                aui.lastTempLockIdTS = 0;
            }, 
            null
        );   
    }
    
    
    
    
    
    protected String[][] giveIpAndLoginAndExAndOtherTags(AuthUserInfo aui, UsernameTokenType usernameToken, Throwable ex)
    {        
        return giveIpAndLoginAndExAndOtherTags(aui, usernameToken, ex, null);
    }
    protected String[][] giveIpAndLoginAndExAndOtherTags(AuthUserInfo aui, UsernameTokenType usernameToken, Throwable ex, String[][] otherTags)
    {        
        String[][] result = new String[][] { 
            new String[] {"IP", getRemoteAddr(true)},
            new String[] {"LOGIN", (usernameToken == null || usernameToken.username == null ? "" : usernameToken.username)},
            new String[] {"USER_ID", (aui == null || aui.user == null || aui.user.user_id == 0 ? "" : ((Integer)aui.user.user_id).toString())}
        };
        if (ex != null)
        {
            result = Common.ConcatArray(result, new String[][]{new String[] {"ex", exTypeForLog(ex)}});
            if (ex instanceof UsernameTokenType.PasswordValidationException)
            {
                UsernameTokenType.PasswordValidationException pwex = (UsernameTokenType.PasswordValidationException)ex;
                result = Common.ConcatArray(result, new String[][]{new String[] {"internalDetails", pwex.internalDetails}});
            }
        }
        if (otherTags != null)
            result = Common.ConcatArray(result, otherTags);
        return result;
    }
    protected String exTypeForLog(Throwable ex)
    {        
        String extyp = null;
        if (ex != null)
        {
            if (ex instanceof UsernameTokenType.PasswordValidationException)
                extyp = "PWE";
            else
                extyp = ex.getClass().getName();
        }
        return extyp;
    }
    protected OthersException WriteToERRORSLogAndGetOthersException(Throwable ex, AuthUserInfo aui, UsernameTokenType usernameToken)
    {
        return WriteToERRORSLogAndGetOthersException(ex, Common.getCurrentSTE(1), aui, usernameToken, null);
    }
    protected OthersException WriteToERRORSLogAndGetOthersException(Throwable ex, StackTraceElement callSTE, AuthUserInfo aui, UsernameTokenType usernameToken, String[][] otherTags)
    {
        String errmsg = Common.nz(ex.getMessage()).trim() + "\r\n\r\n" + Common.getGoodStackTrace(ex, callSTE);
        String[][] addTags = giveIpAndLoginAndExAndOtherTags(aui, usernameToken, ex, otherTags);
        ERRORSLog().write(ex, callSTE, addTags);
        writeToWsErrors(ERRORSLog(), ex, callSTE, addTags);
        return new OthersException(ex.getClass().getName() + ": " + errmsg);
    }
    public static class OthersException extends Exception {
        public OthersException(String Message) {
            super(Message);
        }
        public OthersException(Throwable cause) {
            super(cause);
        }
    }
    protected abstract void writeToWsErrors(Common.Log erlog, Throwable inEx, StackTraceElement callSTE, String[][] otherTags);
    
    
    
    
    
    
    
    
    protected <T> T authAndDo(SecurityHeaderType Security
            , Common.ActionTHROWS beforeAuth, Common.Func1THROWS<AUI, T> afterAuth
            , Common.Func<String[][]> otherTags) 
            throws OthersException, RetryException, UsernameTokenType.PasswordValidationException
    {     
        return authAndDo(Security, beforeAuth, afterAuth, otherTags, OthersException.class, OthersException.class, OthersException.class, null);
    }    
    protected <E1 extends Exception, T> T authAndDo(SecurityHeaderType Security
            , Common.ActionTHROWS beforeAuth, Common.Func1THROWS<AUI, T> afterAuth
            , Common.Func<String[][]> otherTags, Class<E1> cls_E1) 
            throws OthersException, RetryException, UsernameTokenType.PasswordValidationException, E1
    {     
        return authAndDo(Security, beforeAuth, afterAuth, otherTags, cls_E1, OthersException.class, OthersException.class, null);
    }    
    protected <E1 extends Exception, E2 extends Exception, T> T authAndDo(SecurityHeaderType Security
            , Common.ActionTHROWS beforeAuth, Common.Func1THROWS<AUI, T> afterAuth
            , Common.Func<String[][]> otherTags, Class<E1> cls_E1, Class<E2> cls_E2) 
            throws OthersException, RetryException, UsernameTokenType.PasswordValidationException, E1, E2
    {     
        return authAndDo(Security, beforeAuth, afterAuth, otherTags, cls_E1, cls_E2, OthersException.class, null);
    }   
    protected <E1 extends Exception, E2 extends Exception, T> T authAndDo(SecurityHeaderType Security
            , Common.ActionTHROWS beforeAuth, Common.Func1THROWS<AUI, T> afterAuth
            , Common.Func<String[][]> otherTags, Class<E1> cls_E1, Class<E2> cls_E2, Common.Func2<Boolean, Throwable, String[][]> onException) 
            throws OthersException, RetryException, UsernameTokenType.PasswordValidationException, E1, E2
    {     
        return authAndDo(Security, beforeAuth, afterAuth, otherTags, cls_E1, cls_E2, OthersException.class, onException);
    }       
    @SuppressWarnings("unchecked") 
    protected <E1 extends Exception, E2 extends Exception, E3 extends Exception, T> T authAndDo(SecurityHeaderType Security
            , Common.ActionTHROWS beforeAuth, Common.Func1THROWS<AUI, T> afterAuth
            , Common.Func<String[][]> otherTags, Class<E1> cls_E1, Class<E2> cls_E2, Class<E3> cls_E3, Common.Func2<Boolean, Throwable, String[][]> onException) 
            throws OthersException, RetryException, UsernameTokenType.PasswordValidationException, E1, E2, E3
    {           
        Common.Container<AUI> auiC = new Common.Container<>();     
        try
        {   
            if (beforeAuth != null)
                beforeAuth.call();
            
            initOnce();        

            
            //<1. Авторизация> throws PasswordValidationException
            authUser(auiC, Security.UsernameToken);
            //</1. Авторизация>
            
            return afterAuth.call(auiC.value);
        }
        catch (Throwable ex) { 
            boolean isspecified = false;
            if (ex instanceof UsernameTokenType.PasswordValidationException 
                ||
                ex instanceof RetryException 
                || 
                (cls_E1 != null && cls_E1.isAssignableFrom(ex.getClass()))
                || 
                (cls_E2 != null && cls_E2.isAssignableFrom(ex.getClass()))
                || 
                (cls_E3 != null && cls_E3.isAssignableFrom(ex.getClass()))
            )
                isspecified= true;    
            String[][] otherotherTags = null;
            if (onException != null)
                otherotherTags = onException.call(isspecified, ex);
            if (isspecified)
                SpecifiedExceptionsLog().write(Common.getCurrentSTE().getMethodName(), ex.getMessage().trim(), giveIpAndLoginAndExAndOtherTags(auiC.value, Security.UsernameToken, ex, Common.ConcatArray(otherotherTags, otherTags == null ? null : otherTags.call())));

            if (ex instanceof UsernameTokenType.PasswordValidationException)
                throw (UsernameTokenType.PasswordValidationException)ex;
            else if (ex instanceof RetryException)
                throw (RetryException)ex;
            else if (cls_E1 != null && cls_E1.isAssignableFrom(ex.getClass()))
                throw (E1)ex;
            else if (cls_E2 != null && cls_E2.isAssignableFrom(ex.getClass()))
                throw (E2)ex;            
            else if (cls_E3 != null && cls_E3.isAssignableFrom(ex.getClass()))
                throw (E3)ex;            
            else
                throw WriteToERRORSLogAndGetOthersException(ex, Common.getCurrentSTE(), auiC.value, Security.UsernameToken, otherotherTags); 
        }
    }
    
    
    protected void authAndDo(SecurityHeaderType Security
            , Common.ActionTHROWS beforeAuth, Common.Action1THROWS<AUI> afterAuth
            , Common.Func<String[][]> otherTags) 
            throws OthersException, RetryException, UsernameTokenType.PasswordValidationException
    {     
        authAndDo(Security, beforeAuth, afterAuth, otherTags, OthersException.class, OthersException.class, OthersException.class);
    }    
    protected <E1 extends Exception> void authAndDo(SecurityHeaderType Security
            , Common.ActionTHROWS beforeAuth, Common.Action1THROWS<AUI> afterAuth
            , Common.Func<String[][]> otherTags, Class<E1> cls_E1) 
            throws OthersException, RetryException, UsernameTokenType.PasswordValidationException, E1
    {     
        authAndDo(Security, beforeAuth, afterAuth, otherTags, cls_E1, OthersException.class, OthersException.class);
    }    
    protected <E1 extends Exception, E2 extends Exception> void authAndDo(SecurityHeaderType Security
            , Common.ActionTHROWS beforeAuth, Common.Action1THROWS<AUI> afterAuth
            , Common.Func<String[][]> otherTags, Class<E1> cls_E1, Class<E2> cls_E2) 
            throws OthersException, RetryException, UsernameTokenType.PasswordValidationException, E1, E2
    {     
        authAndDo(Security, beforeAuth, afterAuth, otherTags, cls_E1, cls_E2, OthersException.class);
    }   
    protected <E1 extends Exception, E2 extends Exception, E3 extends Exception> void authAndDo(SecurityHeaderType Security
            , Common.ActionTHROWS beforeAuth, Common.Action1THROWS<AUI> afterAuth
            , Common.Func<String[][]> otherTags, Class<E1> cls_E1, Class<E2> cls_E2, Class<E3> cls_E3) 
            throws OthersException, RetryException, UsernameTokenType.PasswordValidationException, E1, E2, E3
    {            
        authAndDo(Security, beforeAuth, (aui) -> { afterAuth.call(aui); return null; }, otherTags, cls_E1, cls_E2, cls_E3, null);
    }
    
    
    
    


    public static <E extends Exception> void ThrowIfSQLExceptionIsMe(SQLException ex, Class<E> cls_E, Common.Func1<String, E> ctor) throws E
    {
        ThrowIfSQLExceptionIsMe(ex, cls_E.getSimpleName(), ctor);
    }   
    public static <E extends Exception> void ThrowIfSQLExceptionIsMe(SQLException ex, String determinant, Common.Func1<String, E> ctor) throws E
    {
        if (ex instanceof PSQLException)
        {
            ServerErrorMessage sm = ((PSQLException)ex).getServerErrorMessage();
            if (determinant.equals((sm).getDetail()) && "P0001".equals(sm.getSQLState()))
                throw ctor.call(sm.getMessage());
        }
    }
    
    
    
    
    
    
    
    
    
    
    public interface XmlEnumEnum<E extends Enum<E>> 
    {        
        @SuppressWarnings("unchecked")
        default String getAlias()
        {
            return Common.getXmlEnumValue((E)this);
        }
        public static <E extends Enum<E> & XmlEnumEnum<E>> E getByAlias(String alias, Class<E> enumClass)
        {
            return Common.getByXmlEnumValue(alias, enumClass);
        }
    }
    
    
    
    
    public String[][] file_write_on_exception(SecurityHeaderType security, byte[] argValue, String argName, String path_mid)
    {
        String path_prefix = Common.SlashOnEnd(initParameters.logs_path()) + serviceName + "_" + path_mid + "_Files";
        String f;
        String[][] otherTags = new String[1][];
        if (argValue != null && argValue.length > 0)
        {
            String u = security == null || security.UsernameToken == null || security.UsernameToken.username == null 
                ? "----" : security.UsernameToken.username;
            String fd = Common.SlashOnEnd(Common.SlashOnEnd(path_prefix) + Common.NowToString("yyyyMMdd"));
            f =  fd + u + "_" + System.currentTimeMillis() + ".txt.gzip"; 
            try
            {
                if (!Files.exists(Paths.get(fd)))
                    Files.createDirectories(Paths.get(fd));
                Files.write(Paths.get(f), argValue);
                otherTags[0] = new String[] { argName + "_file", f };
            }
            catch(Throwable thth)
            {
                otherTags[0] = new String[] { argName + "_file_write_error", thth.toString() };
            }
        }
        else
        {
            otherTags[0] = new String[] { argName + "_is_null", "true" };
        }
        return otherTags;
    }
}