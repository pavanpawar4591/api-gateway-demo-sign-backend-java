/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.aliyun.api.gateway.demo.sign.backend;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * å�Žç«¯æœ�åŠ¡ç­¾å��ç¤ºä¾‹
 */
public class Sign {
    //All key entries in the HTTP request header that are involved in the signature calculation should be separated by commas
    private static final String CA_PROXY_SIGN_HEADERS = "X-Ca-Proxy-Signature-Headers";
    //Signature of the API gateway calculation
    private static final String CA_PROXY_SIGN = "X-Ca-Proxy-Signature";
    //The key used by the API gateway to calculate the signature
    private static final String CA_PROXY_SIGN_SECRET_KEY = "X-Ca-Proxy-Signature-Secret-Key";
    //Signature algorithm HmacSha256
    public static final String HMAC_SHA256 = "HmacSHA256";
    //Line breaks

    private static char LF = '\n';
    //coding
    private static final String ENCODING = "UTF-8";
    //HTTP POST
    private static final String HTTP_METHOD_POST = "post";
    //HTTP PUT
    private static final String HTTP_METHOD_PUT = "put";
    //HTTP HEADER is converted to lowercase (part of the WEB container to receive all the HEADER KEY are lowercase
    private static final boolean HTTP_HEADER_TO_LOWER_CASE = true;

    //signature key map, used to store many pairs of server-side signature calculation key, once the key is being used to leak, only need to key list of other keys configured to the gateway can be key hot replacement

    private static Map<String, String> signSecretMap = new HashMap<String, String>();

    static {
        //// TODO: modify it to your own key combination

        signSecretMap.put("DemoKey1", "DemoSecret1");
        signSecretMap.put("DemoKey2", "DemoSecret2");
        signSecretMap.put("DemoKey3", "DemoSecret3");
    }

    /**
     * Demo
     *
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        String uri = "/demo/uri";
        String httpMethod = "POST";
        Map<String, String> headers = new HashMap<String, String>();
        headers.put(CA_PROXY_SIGN, "vYpUZCP7O+xF0Ynumi8+O8GV3JveCA32nEXLucpf+QQ=");
        headers.put(CA_PROXY_SIGN_HEADERS, "HeaderKey1,HeaderKey2");
        headers.put(CA_PROXY_SIGN_SECRET_KEY, "DemoKey1");
        headers.put("HeaderKey1", "HeaderValue1");
        headers.put("HeaderKey2", "HeaderValue2");

        Map<String, Object> paramsMap = new HashMap<String, Object>();
        paramsMap.put("QueryKey1", "QueryValue1");
        paramsMap.put("QueryKey2", "QueryValue2");
        paramsMap.put("FormKey1", "FormValue1");
        paramsMap.put("FormKey2", "FormValue2");

        byte[] inputStreamBytes = new byte[]{};

        String gatewaySign = headers.get(CA_PROXY_SIGN);
        System.out.println("API Gateway Signature :" + gatewaySign);

        String serviceSign = serviceSign(uri, httpMethod, headers, paramsMap, inputStreamBytes);
        System.out.println("Server signature:" + serviceSign);

        System.out.println("Whether the signature is the same:" + gatewaySign.equals(serviceSign));
    }

    /**
     * Calculate the HTTP request signature
     *
     * @param uri             Raw HTTP request PATH (does not include Query)

     * @param httpMethod       Raw HTTP request method

     * @param headers          Raw HTTP requests all request headers
     * @param paramsMap        åŽŸå§‹HTTPè¯·æ±‚æ‰€æœ‰Query+Formå�‚æ•°
     * @param inputStreamBytes åŽŸå§‹HTTPè¯·æ±‚Bodyä½“ï¼ˆä»…å½“è¯·æ±‚ä¸ºPOST/PUTä¸”é�žè¡¨å�•è¯·æ±‚æ‰�éœ€è¦�è®¾ç½®æ­¤å±žæ€§,è¡¨å�•å½¢å¼�çš„éœ€è¦�å°†å�‚æ•°æ”¾åˆ°paramsMapä¸­ï¼‰
     * @return ç­¾å��ç»“æžœ
     * @throws Exception
     */
    public static String serviceSign(String uri, String httpMethod, Map<String, String> headers, Map<String, Object> paramsMap, byte[] inputStreamBytes) throws Exception {
        Map<String, String> headersToSign = buildHeadersToSign(headers);
        String bodyMd5 = buildBodyMd5(httpMethod, inputStreamBytes);
        String resourceToSign = buildResource(uri, paramsMap);
        String stringToSign = buildStringToSign(headersToSign, resourceToSign, httpMethod, bodyMd5);

        Mac hmacSha256 = Mac.getInstance(HMAC_SHA256);
        String secret = signSecretMap.get(headers.get(HTTP_HEADER_TO_LOWER_CASE ? CA_PROXY_SIGN_SECRET_KEY.toLowerCase() : CA_PROXY_SIGN_SECRET_KEY));

        byte[] keyBytes = secret.getBytes(ENCODING);
        hmacSha256.init(new SecretKeySpec(keyBytes, 0, keyBytes.length, HMAC_SHA256));

        return new String(Base64.encodeBase64(hmacSha256.doFinal(stringToSign.getBytes(ENCODING))), ENCODING);
    }

    /**
     * æž„å»ºBodyMd5
     *
     * @param httpMethod       HTTPè¯·æ±‚æ–¹æ³•
     * @param inputStreamBytes HTTPè¯·æ±‚Bodyä½“å­—èŠ‚æ•°ç»„
     * @return Body Md5å€¼
     * @throws IOException
     */
    private static String buildBodyMd5(String httpMethod, byte[] inputStreamBytes) throws IOException {
        if (inputStreamBytes == null) {
            return null;
        }

        if (!httpMethod.equalsIgnoreCase(HTTP_METHOD_POST) && !httpMethod.equalsIgnoreCase(HTTP_METHOD_PUT)) {
            return null;
        }

        InputStream inputStream = new ByteArrayInputStream(inputStreamBytes);
        byte[] bodyBytes = IOUtils.toByteArray(inputStream);
        if (bodyBytes != null && bodyBytes.length > 0) {
            return base64AndMD5(bodyBytes).trim();
        }
        return null;
    }

    /**
     * å°†Mapè½¬æ�¢ä¸ºç”¨&å�Š=æ‹¼æŽ¥çš„å­—ç¬¦ä¸²
     */
    private static String buildMapToSign(Map<String, Object> paramMap) {
        StringBuilder builder = new StringBuilder();

        for (Map.Entry<String, Object> e : paramMap.entrySet()) {
            if (builder.length() > 0) {
                builder.append('&');
            }

            String key = e.getKey();
            Object value = e.getValue();

            if (value != null) {
                if (value instanceof List) {
                    List list = (List) value;
                    if (list.size() == 0) {
                        builder.append(key);
                    } else {
                        builder.append(key).append("=").append(String.valueOf(list.get(0)));
                    }
                } else if (value instanceof Object[]) {
                    Object[] objs = (Object[]) value;
                    if (objs.length == 0) {
                        builder.append(key);
                    } else {
                        builder.append(key).append("=").append(String.valueOf(objs[0]));
                    }
                } else {
                    builder.append(key).append("=").append(String.valueOf(value));
                }
            }
        }

        return builder.toString();
    }

    /**
     * æž„å»ºå�‚ä¸Žç­¾å��çš„HTTPå¤´
     * <pre>
     * ä¼ å…¥çš„Headerså¿…é¡»å°†é»˜è®¤çš„ISO-8859-1è½¬æ�¢ä¸ºUTF-8ä»¥æ”¯æŒ�ä¸­æ–‡
     * </pre>
     *
     * @param headers HTTPè¯·æ±‚å¤´
     * @return æ‰€æœ‰å�‚ä¸Žç­¾å��è®¡ç®—çš„HTTPè¯·æ±‚å¤´
     */
    private static Map<String, String> buildHeadersToSign(Map<String, String> headers) {
        Map<String, String> headersToSignMap = new TreeMap<String, String>();

        String headersToSignString = headers.get(HTTP_HEADER_TO_LOWER_CASE ? CA_PROXY_SIGN_HEADERS.toLowerCase() : CA_PROXY_SIGN_HEADERS);

        if (headersToSignString != null) {
            for (String headerKey : headersToSignString.split("\\,")) {
                headersToSignMap.put(headerKey, headers.get(HTTP_HEADER_TO_LOWER_CASE ? headerKey.toLowerCase() : headerKey));
            }
        }

        return headersToSignMap;
    }

    /**
     * ç»„ç»‡å¾…è®¡ç®—ç­¾å��å­—ç¬¦ä¸²
     *
     * @param headers        HTTPè¯·æ±‚å¤´
     * @param resourceToSign Uri+è¯·æ±‚å�‚æ•°çš„ç­¾å��å­—ç¬¦ä¸²
     * @param method         HTTPæ–¹æ³•
     * @param bodyMd5        Body Md5å€¼
     * @return å¾…è®¡ç®—ç­¾å��å­—ç¬¦ä¸²
     */
    private static String buildStringToSign(Map<String, String> headers, String resourceToSign, String method, String bodyMd5) {
        StringBuilder sb = new StringBuilder();
        sb.append(method).append(LF);
        if (StringUtils.isNotBlank(bodyMd5)) {
            sb.append(bodyMd5);
        }
        sb.append(LF);
        sb.append(buildHeaders(headers));
        sb.append(resourceToSign);

        return sb.toString();
    }

    /**
     * ç»„ç»‡Headersç­¾å��ç­¾å��å­—ç¬¦ä¸²
     *
     * @param headers HTTPè¯·æ±‚å¤´
     * @return Headersç­¾å��ç­¾å��å­—ç¬¦ä¸²
     */
    private static String buildHeaders(Map<String, String> headers) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getValue() != null) {
                sb.append(e.getKey().toLowerCase()).append(':').append(e.getValue()).append(LF);
            }
        }
        return sb.toString();
    }

    /**
     * ç»„ç»‡Uri+è¯·æ±‚å�‚æ•°çš„ç­¾å��å­—ç¬¦ä¸²
     *
     * @param uri       HTTPè¯·æ±‚uri,ä¸�åŒ…å�«Query
     * @param paramsMap HTTPè¯·æ±‚æ‰€æœ‰å�‚æ•°ï¼ˆQuery+Formå�‚æ•°ï¼‰
     * @return Uri+è¯·æ±‚å�‚æ•°çš„ç­¾å��å­—ç¬¦ä¸²
     */
    private static String buildResource(String uri, Map<String, Object> paramsMap) {
        StringBuilder builder = new StringBuilder();

        // uri
        builder.append(uri);

        // Query+Form
        TreeMap<String, Object> sortMap = new TreeMap<String, Object>();
        sortMap.putAll(paramsMap);


        // æœ‰Query+Formå�‚æ•°
        if (sortMap.size() > 0) {
            builder.append('?');
            builder.append(buildMapToSign(sortMap));
        }

        return builder.toString();
    }

    /**
     * å…ˆè¿›è¡ŒMD5æ‘˜è¦�å†�è¿›è¡ŒBase64ç¼–ç �èŽ·å�–æ‘˜è¦�å­—ç¬¦ä¸²
     *
     * @param bytes å¾…è®¡ç®—å­—èŠ‚æ•°ç»„
     * @return
     */
    public static String base64AndMD5(byte[] bytes) {
        if (bytes == null) {
            throw new IllegalArgumentException("bytes can not be null");
        }

        try {
            final MessageDigest md = MessageDigest.getInstance("MD5");
            md.reset();
            md.update(bytes);
            final Base64 base64 = new Base64();

            return new String(base64.encode(md.digest()));
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("unknown algorithm MD5");
        }
    }
}