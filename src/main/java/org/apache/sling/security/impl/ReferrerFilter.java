/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.sling.security.impl;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicyOption;
import org.osgi.service.http.whiteboard.HttpWhiteboardConstants;
import org.osgi.service.http.whiteboard.Preprocessor;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(
        service = Preprocessor.class,
        property = {
                HttpWhiteboardConstants.HTTP_WHITEBOARD_CONTEXT_SELECT + "=(" + HttpWhiteboardConstants.HTTP_WHITEBOARD_CONTEXT_NAME + "=*)",
                "felix.webconsole.label=slingreferrerfilter",
                "felix.webconsole.title=Sling Referrer Filter",
                "felix.webconsole.configprinter.modes=always"
        }
)
@Designate(ocd = ReferrerFilter.Config.class)
public class ReferrerFilter implements Preprocessor {

    /**
     * Request header providing the clients user agent information used
     * by {@link #isBrowserRequest(HttpServletRequest)} to decide whether
     * a request is probably sent by a browser or not.
     */
    private static final String USER_AGENT = "User-Agent";

    /**
     * String contained in a {@link #USER_AGENT} header indicating a Mozilla
     * class browser. Examples of such browsers are Firefox (generally Gecko
     * based browsers), Safari, Chrome (probably generally WebKit based
     * browsers), and Microsoft IE.
     */
    private static final String BROWSER_CLASS_MOZILLA = "Mozilla";

    /**
     * String contained in a {@link #USER_AGENT} header indicating a Opera class
     * browser. The only known browser in this class is the Opera browser.
     */
    private static final String BROWSER_CLASS_OPERA = "Opera";

    /**
     * Logger.
     */
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @ObjectClassDefinition(
            name = "Apache Sling Referrer Filter",
            description = "Request filter checking the referrer of modification requests and denying request with a 403 in case the referrer is not allowed"
    )
    public @interface Config {

        /**
         * Allow empty property.
         */
        @AttributeDefinition(
                name = "Allow Empty",
                description = "Allow an empty or missing referrer"
        )
        boolean allow_empty() default false;

        /**
         * Allow referrer uri hosts property.
         */
        @AttributeDefinition(
                name = "Allow Hosts",
                description = "List of allowed hosts for the referrer which are added to the list of default hosts. "
                        + "It is matched against the full referrer URL in the format \"<scheme>://<host>:<port>\". "
                        + "If port is 0, it is not taken into consideration. The default list contains all host names "
                        + "and IPs bound to all NICs found in the system plus \"localhost\", \"127.0.0.1\", \"[::1]\" for protocols \"http\" and \"https\". "
                        + "If given value does not have a \":\" entries for both http and https are transparently generated."
        )
        String[] allow_hosts() default {};

        /**
         * Allow referrer regex hosts property
         */
        @AttributeDefinition(
                name = "Allow Regexp Host",
                description = "List of allowed regular expression for the referrer. "
                        + "It is matched against the full referrer URL in the format \"<scheme>://<host>:<port>\". "
                        + "Evaluated in addition to the default list and the given allowed hosts (see above)!"
        )
        String[] allow_hosts_regexp() default {};

        /**
         * Filtered methods property
         */
        @AttributeDefinition(
                name = "Filter Methods",
                description = "These methods are filtered by the filter"
        )
        String[] filter_methods() default {"POST", "PUT", "DELETE", "COPY", "MOVE"};

        /**
         * Excluded regexp user agents property
         */
        @AttributeDefinition(
                name = "Exclude Regexp User Agent",
                description = "List of regexp for user agents not to check the referrer"
        )
        String[] exclude_agents_regexp() default {};

        /**
         * Excluded the configured paths from the referrer check
         */
        @AttributeDefinition(
                name = "Exclude Paths",
                description = "List of paths for which not to check the referrer"
        )
        String[] exclude_paths() default {};
    }


    /**
     * Do we allow empty referrer?
     */
    private final boolean allowEmpty;

    /** Allowed uri referrers */
    private final URL[] allowedUriReferrers;

    /** Allowed regexp referrers */
    private final Pattern[] allowedRegexReferrers;

    /** Methods to be filtered. */
    private final String[] filterMethods;

    /** User agents to be excluded */
    private final Pattern[] excludedRegexUserAgents;

    /** Paths to be excluded */
    private final String[] excludedPaths;

    /**
     * Create a default list of referrers
     */
    private Set<String> getDefaultAllowedReferrers() {
        final Set<String> referrers = new HashSet<>();
        try {
            final Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();

            while (ifaces.hasMoreElements()) {
                final NetworkInterface iface = ifaces.nextElement();
                logger.info("Adding Allowed referers for Interface: {}", iface.getDisplayName());
                final Enumeration<InetAddress> ias = iface.getInetAddresses();
                while (ias.hasMoreElements()) {
                    final InetAddress ia = ias.nextElement();
                    final String address = ia.getHostAddress().trim().toLowerCase();
                    if (ia instanceof Inet4Address) {
                        referrers.add("http://" + address + ":0");
                        referrers.add("https://" + address + ":0");
                    }
                    if (ia instanceof Inet6Address) {
                        referrers.add("http://[" + address + "]" + ":0");
                        referrers.add("https://[" + address + "]" + ":0");
                    }
                }
            }
        } catch (final SocketException se) {
            logger.error("Unable to detect network interfaces", se);
        }
        referrers.add("http://localhost" + ":0");
        referrers.add("http://127.0.0.1" + ":0");
        referrers.add("http://[::1]" + ":0");
        referrers.add("https://localhost" + ":0");
        referrers.add("https://127.0.0.1" + ":0");
        referrers.add("https://[::1]" + ":0");

        return referrers;
    }

    private void add(final List<URL> urls, final String ref) {
        try {
            final URL u = new URL(ref);
            urls.add(u);
        } catch (final MalformedURLException mue) {
            logger.warn("Unable to create URL from {} : {}", ref, mue.getMessage());
        }
    }

    /**
     * Create URLs out of the uri referrer set
     */
    private URL[] createReferrerUrls(final Set<String> referrers) {
        final List<URL> urls = new ArrayList<>();

        for (final String ref : referrers) {
            final int pos = ref.indexOf("://");
            // valid url?
            if (pos != -1) {
                this.add(urls, ref);
            } else {
                this.add(urls, "http://" + ref + ":0");
                this.add(urls, "https://" + ref + ":0");
            }
        }
        return urls.toArray(new URL[0]);
    }

    /**
     * Create Patterns out of the regular expression referrer list
     */
    private Pattern[] createRegexPatterns(final Collection<String> regexps) {
        final List<Pattern> patterns = new ArrayList<>();
        if (regexps != null) {
            for (final String regexp : regexps) {
                try {
                    final Pattern pattern = Pattern.compile(regexp);
                    patterns.add(pattern);
                } catch (final Exception e) {
                    logger.warn("Unable to create Pattern from {} : {}", regexp, e.getMessage());
                }
            }
        }
        return patterns.toArray(new Pattern[0]);
    }

    private Collection<String> mergeValues(String[] primary, List<ReferrerFilterAmendment> amendments,
            Function<ReferrerFilterAmendment, String[]> extractor) {
        Set<String> consolidated = new HashSet<>();
        if (primary != null) {
            Arrays.stream(primary).forEach(consolidated::add);
        }
        if (amendments != null) {
            amendments.stream().map(extractor::apply).forEach(v -> Arrays.stream(v).forEach(consolidated::add));
        }
        return consolidated;
    }

    @Activate
    public ReferrerFilter(final Config config,
            @Reference(policyOption = ReferencePolicyOption.GREEDY, cardinality = ReferenceCardinality.MULTIPLE, service=ReferrerFilterAmendment.class) List<ReferrerFilterAmendment> amendments) {
        this.allowEmpty = config.allow_empty();
        this.allowedRegexReferrers = createRegexPatterns(
                mergeValues(config.allow_hosts_regexp(), amendments, a -> a.allowHostsRegex()));
        this.excludedRegexUserAgents = createRegexPatterns(
                mergeValues(config.exclude_agents_regexp(), amendments, a -> a.excludeAgentsRegex()));
        this.excludedPaths = mergeValues(config.exclude_paths(), amendments, a -> a.excludePaths()).toArray(new String[0]);

        final Set<String> allowUriReferrers = getDefaultAllowedReferrers();
        if (config.allow_hosts() != null) {
            allowUriReferrers.addAll(
                    mergeValues(config.allow_hosts(), amendments, a -> a.allowHosts()));
        }
        this.allowedUriReferrers = createReferrerUrls(allowUriReferrers);

        String[] methods = config.filter_methods();
        if (methods != null) {
            final List<String> values = new ArrayList<>();
            for (final String m : methods) {
                if (m != null && m.trim().length() > 0) {
                    values.add(m.trim().toUpperCase());
                }
            }
            if (values.isEmpty()) {
                methods = null;
            } else {
                methods = values.toArray(new String[values.size()]);
            }
        }
        this.filterMethods = methods;
    }

    private boolean isModification(final HttpServletRequest req) {
        final String method = req.getMethod();
        if (filterMethods != null) {
            for (final String m : filterMethods) {
                if (m.equals(method)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public void doFilter(final ServletRequest req,
                         final ServletResponse res,
                         final FilterChain chain)
            throws IOException, ServletException {
        if (req instanceof HttpServletRequest && res instanceof HttpServletResponse) {
            final HttpServletRequest request = (HttpServletRequest) req;

            // is this a modification request from a browser
            if (this.isBrowserRequest(request) && this.isModification(request)) {
                if (!this.isValidRequest(request)) {
                    final HttpServletResponse response = (HttpServletResponse) res;
                    // we use 403
                    response.sendError(403);
                    return;
                }
            }
        }
        chain.doFilter(req, res);
    }

    static final class HostInfo {
        String host;
        String scheme;
        int port;

        String toURI() {
            return scheme + "://" + host + ":" + port;
        }
    }

    HostInfo getHost(final String referrer) {
        final int startPos = referrer.indexOf("://") + 3;
        if (startPos == 2 || startPos == referrer.length()) {
            // we consider this illegal
            return null;
        }
        final HostInfo info = new HostInfo();
        info.scheme = referrer.substring(0, startPos - 3);

        final int paramStart = referrer.indexOf('?');
        final String hostAndPath = (paramStart == -1 ? referrer : referrer.substring(0, paramStart));
        final int endPos = hostAndPath.indexOf('/', startPos);
        final String hostPart = (endPos == -1 ? hostAndPath.substring(startPos) : hostAndPath.substring(startPos, endPos));
        final int hostNameStart = hostPart.indexOf('@') + 1;
        final int hostNameEnd = hostPart.lastIndexOf(':');
        if (hostNameEnd < hostNameStart) {
            info.host = hostPart.substring(hostNameStart);
            if (info.scheme.equals("http")) {
                info.port = 80;
            } else if (info.scheme.equals("https")) {
                info.port = 443;
            }
        } else {
            info.host = hostPart.substring(hostNameStart, hostNameEnd);
            info.port = Integer.valueOf(hostPart.substring(hostNameEnd + 1));
        }
        return info;
    }

    boolean isValidRequest(final HttpServletRequest request) {
        // ignore referrer check if the request matches any of the configured excluded path.
        if (isExcludedPath(request)) {
            return true;
        }
        
        String referrer = request.getHeader("referer");
        // use the origin if the referrer is not set
        if (referrer == null || referrer.trim().length() == 0) {
            referrer = request.getHeader("origin");
        }

        // check for missing/empty referrer
        if (referrer == null || referrer.trim().length() == 0) {
            if (!this.allowEmpty) {
                this.logger.info("Rejected empty referrer header for {} request to {}", request.getMethod(), request.getRequestURI());
            }
            return this.allowEmpty;
        }
        // check for relative referrer - which is always allowed
        if (!referrer.contains(":/")) {
            return true;
        }

        final HostInfo info = getHost(referrer);
        if (info == null) {
            // if this is invalid we just return invalid
            this.logger.info("Rejected illegal referrer header for {} request to {} : {}", request.getMethod(), request.getRequestURI(), referrer);
            return false;
        }

        // allow the request if the host name of the referrer is
        // the same as the request's host name
        if (info.host.equals(request.getServerName())) {
            return true;
        }

        // allow the request if the referrer matches any of the allowed referrers
        boolean valid = isValidUriReferrer(info) || isValidRegexReferrer(info);

        if (!valid) {
            this.logger.info("Rejected referrer header for {} request to {} : {}", request.getMethod(), request.getRequestURI(), referrer);
        }
        return valid;
    }

    /**
     * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
     */
    @Override
    public void init(final FilterConfig config) throws ServletException {
        // nothing to do
    }

    /**
     * @see javax.servlet.Filter#destroy()
     */
    @Override
    public void destroy() {
        // nothing to do
    }

    /**
     * @param hostInfo The hostInfo to check for validity
     * @return <code>true</code> if the hostInfo matches any of the allowed URI referrer.
     */
    private boolean isValidUriReferrer(HostInfo hostInfo) {
        for (final URL ref : this.allowedUriReferrers) {
            if (hostInfo.host.equals(ref.getHost()) && hostInfo.scheme.equals(ref.getProtocol())) {
                if (ref.getPort() == 0 || hostInfo.port == ref.getPort()) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @param hostInfo The hostInfo to check for validity
     * @return <code>true</code> if the hostInfo matches any of the allowed regexp referrer.
     */
    private boolean isValidRegexReferrer(HostInfo hostInfo) {
        for (final Pattern ref : this.allowedRegexReferrers) {
            String url = hostInfo.toURI();
            if (ref.matcher(url).matches()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns <code>true</code> if the path info associated with the given request is contained in the configured excluded paths.
     *
     * @param request The request to check
     * @return <code>true</code> if the path-info associate with the given request is contained in the configured excluded paths.
     */
    private boolean isExcludedPath(HttpServletRequest request) {
        if (this.excludedPaths == null) {
            return false;
        }
        String path = request.getPathInfo();
        for (final String excludedPath : this.excludedPaths) {
            if (excludedPath != null && excludedPath.equals(path)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Returns <code>true</code> if the provided user agent matches any present exclusion regexp pattern.
     *
     * @param userAgent The user agent string to check
     * @return <code>true</code> if the user agent matches any exclusion pattern.
     */
    private boolean isExcludedRegexUserAgent(String userAgent) {
        for (final Pattern pattern : this.excludedRegexUserAgents) {
            if (pattern.matcher(userAgent).matches()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns <code>true</code> if the given request can be assumed to be sent
     * by a client browser such as Firefix, Internet Explorer, etc.
     * <p>
     * This method inspects the <code>User-Agent</code> header and returns
     * <code>true</code> if the header contains the string <i>Mozilla</i> (known
     * to be contained in Firefox, Internet Explorer, WebKit-based browsers
     * User-Agent) or <i>Opera</i> (known to be contained in the Opera
     * User-Agent).
     *
     * @param request The request to inspect
     * @return <code>true</code> if the request is assumed to be sent by a
     * browser.
     */
    protected boolean isBrowserRequest(final HttpServletRequest request) {
        final String userAgent = request.getHeader(USER_AGENT);
        return userAgent != null
                && (userAgent.contains(BROWSER_CLASS_MOZILLA) || userAgent.contains(BROWSER_CLASS_OPERA))
                && !isExcludedRegexUserAgent(userAgent);
    }

    /**
     * Print out the allowedReferrers
     * @see org.apache.felix.webconsole.ConfigurationPrinter#printConfiguration(java.io.PrintWriter)
     * @param pw the PrintWriter object
     */
    public void printConfiguration(final PrintWriter pw) {
        pw.println("Current Apache Sling Referrer Filter Allowed Referrers:");
        pw.println();
        for (final URL url : allowedUriReferrers) {
            pw.println(url.toString());
        }
        for (final Pattern pattern : allowedRegexReferrers) {
            pw.println(pattern.toString());
        }
    }
}
