/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sling.security.impl;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ValueMap;
import org.apache.sling.api.wrappers.SlingHttpServletResponseWrapper;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.metatype.annotations.Designate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(
        service = Filter.class,
        property = {"sling.filter.scope=request", "sling.filter.scope=forward", "service.ranking:Integer=25000"})
@Designate(ocd = ContentDispositionFilterConfiguration.class)
public class ContentDispositionFilter implements Filter {

    /**
     * Logger.
     */
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private static final List<String> supportedMethods = Arrays.asList("GET", "HEAD");

    /**
     * Set of paths
     */
    final Set<String> contentDispositionPaths;

    /**
     * Array of prefixes of paths
     */
    private final String[] contentDispositionPathsPfx;

    Set<String> contentDispositionExcludedPaths;

    private final Map<String, Set<String>> contentTypesMapping;

    private final boolean enableContentDispositionAllPaths;

    @Activate
    public ContentDispositionFilter(final ContentDispositionFilterConfiguration configuration) {

        Set<String> paths = new HashSet<>();
        List<String> pfxs = new ArrayList<>();
        Map<String, Set<String>> contentTypesMap = new HashMap<>();

        // check for null till we upgrade to DS 1.4 (https://osgi.org/bugzilla/show_bug.cgi?id=208)
        if (configuration.sling_content_disposition_paths() != null) {
            for (String path : configuration.sling_content_disposition_paths()) {
                path = path.trim();
                if (path.length() > 0) {
                    int idx = path.indexOf('*');
                    int colonIdx = path.indexOf(":");

                    if (colonIdx > -1 && colonIdx < idx) {
                        // ':'  in paths is not allowed
                        logger.info(
                                "wildcard ('*') in content type is not allowed, but found content type with value '{}'",
                                path.substring(colonIdx));
                    } else {
                        String p = null;
                        if (idx >= 0) {
                            if (idx > 0) {
                                p = path.substring(0, idx);
                                pfxs.add(p);
                            } else {
                                // we don't allow "*" - that would defeat the
                                // purpose.
                                logger.info("catch-all wildcard for paths not allowed.");
                            }
                        } else {
                            if (colonIdx > -1) {
                                p = path.substring(0, colonIdx);
                            } else {
                                p = path;
                            }
                            paths.add(p);
                        }
                        if (colonIdx != -1 && p != null) {
                            Set<String> contentTypes = getContentTypes(path.substring(colonIdx + 1));
                            contentTypesMap.put(p, contentTypes);
                        }
                    }
                }
            }
        }
        contentDispositionPaths = paths.isEmpty() ? Collections.emptySet() : paths;
        contentDispositionPathsPfx = pfxs.toArray(new String[0]);
        contentTypesMapping = contentTypesMap.isEmpty() ? Collections.emptyMap() : contentTypesMap;

        enableContentDispositionAllPaths = configuration.sling_content_disposition_all_paths();

        String[] contentDispositionExcludedPathsArray = configuration.sling_content_disposition_excluded_paths() != null
                ? configuration.sling_content_disposition_excluded_paths()
                : new String[] {};

        contentDispositionExcludedPaths = new HashSet<>(Arrays.asList(contentDispositionExcludedPathsArray));

        logger.info(
                "Initialized. content disposition paths: {}, content disposition paths-pfx {}, content disposition excluded paths: {}. Enable Content Disposition for all paths is set to {}",
                contentDispositionPaths,
                contentDispositionPathsPfx,
                contentDispositionExcludedPaths,
                enableContentDispositionAllPaths);
    }

    @Override
    public void init(FilterConfig filterConfig) {
        // nothing to do
    }

    @Override
    public void destroy() {
        // nothing to do
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        final SlingHttpServletRequest slingRequest = (SlingHttpServletRequest) request;
        final SlingHttpServletResponse slingResponse = (SlingHttpServletResponse) response;

        final RewriterResponse rewriterResponse = new RewriterResponse(slingRequest, slingResponse);

        chain.doFilter(request, rewriterResponse);
    }

    // ---------- PRIVATE METHODS ---------

    private static Set<String> getContentTypes(String contentTypes) {
        Set<String> contentTypesSet = new HashSet<>();
        if (contentTypes != null && contentTypes.length() > 0) {
            String[] contentTypesArray = contentTypes.split(",");
            Collections.addAll(contentTypesSet, contentTypesArray);
        }
        return contentTypesSet;
    }

    // ----------- INNER CLASSES ------------

    protected class RewriterResponse extends SlingHttpServletResponseWrapper {

        private static final String CONTENT_DISPOSTION = "Content-Disposition";

        private static final String CONTENT_DISPOSTION_ATTACHMENT = "attachment";

        private static final String CONTENT_TYPE = "Content-Type";

        private static final String PROP_JCR_DATA = "jcr:data";

        private static final String JCR_CONTENT_LEAF = "jcr:content";

        static final String ATTRIBUTE_NAME =
                "org.apache.sling.security.impl.ContentDispositionFilter.RewriterResponse.contentType";

        /**
         * The current request.
         */
        private final SlingHttpServletRequest request;

        private final Resource resource;

        /**
         * The content type this wrapper has already evaluated the
         * Content-Disposition header for. The {@link #ATTRIBUTE_NAME} request
         * attribute alone is not sufficient: the attribute is shared with the
         * wrappers created for nested (forward) dispatches, and a value cached
         * by an outer dispatch for a different resource must not suppress the
         * header evaluation for this wrapper's own resource.
         */
        private String evaluatedContentType;

        public RewriterResponse(SlingHttpServletRequest request, SlingHttpServletResponse wrappedResponse) {
            super(wrappedResponse);
            this.request = request;
            this.resource = request.getResource();
        }

        @Override
        public void reset() {
            request.removeAttribute(ATTRIBUTE_NAME);
            this.evaluatedContentType = null;
            super.reset();
        }

        /**
         * @see javax.servlet.ServletResponseWrapper#setContentType(java.lang.String)
         */
        @Override
        public void setContentType(String type) {
            if (supportedMethods.contains(request.getMethod())) {
                String previousContentType = (String) request.getAttribute(ATTRIBUTE_NAME);

                // only skip the evaluation if THIS wrapper has already
                // evaluated the header decision for this content type: the
                // request attribute may have been populated by the wrapper of
                // another (outer) dispatch for a different resource
                if (previousContentType != null
                        && previousContentType.equals(type)
                        && previousContentType.equals(this.evaluatedContentType)) {
                    super.setContentType(type);
                    return;
                }

                this.evaluatedContentType = type;
                request.setAttribute(ATTRIBUTE_NAME, type);

                applyContentDisposition(type);
            }
            super.setContentType(type);
        }

        /**
         * Setting the "Content-Type" header is equivalent to calling
         * {@link #setContentType(String)} and must be mediated the same way.
         *
         * @see javax.servlet.http.HttpServletResponseWrapper#setHeader(java.lang.String, java.lang.String)
         */
        @Override
        public void setHeader(String name, String value) {
            if (CONTENT_TYPE.equalsIgnoreCase(name)) {
                this.setContentType(value);
                return;
            }
            super.setHeader(name, value);
        }

        /**
         * @see javax.servlet.http.HttpServletResponseWrapper#addHeader(java.lang.String, java.lang.String)
         */
        @Override
        public void addHeader(String name, String value) {
            if (CONTENT_TYPE.equalsIgnoreCase(name)) {
                this.setContentType(value);
                return;
            }
            super.addHeader(name, value);
        }

        /**
         * the content disposition decision is evaluated before the body can be written.
         *
         * @see javax.servlet.ServletResponseWrapper#getOutputStream()
         */
        @Override
        public ServletOutputStream getOutputStream() throws IOException {
            this.ensureContentDispositionApplied();
            return super.getOutputStream();
        }

        /**
         * @see javax.servlet.ServletResponseWrapper#getWriter()
         */
        @Override
        public PrintWriter getWriter() throws IOException {
            this.ensureContentDispositionApplied();
            return super.getWriter();
        }

        // ---------- PRIVATE METHODS ---------

        private void ensureContentDispositionApplied() {
            if (supportedMethods.contains(request.getMethod()) && request.getAttribute(ATTRIBUTE_NAME) == null) {
                applyContentDisposition(this.getContentType());
            }
        }

        private void applyContentDisposition(final String type) {
            String resourcePath = resource.getPath();

            // A file's jcr:content child node carries the file's binary
            // (jcr:data) directly and thus serves the very same bytes
            // under a second address. Match such a resource against the
            // configured exact path of the file itself as well, so that
            // /path/file.ext/jcr:content cannot bypass an exact entry
            // protecting /path/file.ext.
            String configMatchPath = resourcePath;
            if (configMatchPath.endsWith("/" + JCR_CONTENT_LEAF)) {
                configMatchPath =
                        configMatchPath.substring(0, configMatchPath.length() - JCR_CONTENT_LEAF.length() - 1);
            }

            if (!contentDispositionExcludedPaths.contains(resourcePath)) {

                if (enableContentDispositionAllPaths) {
                    setContentDisposition(resource);
                } else {

                    boolean contentDispositionAdded = false;
                    if (contentDispositionPaths.contains(resourcePath)
                            || contentDispositionPaths.contains(configMatchPath)) {

                        String mappingKey =
                                contentTypesMapping.containsKey(resourcePath) ? resourcePath : configMatchPath;
                        if (contentTypesMapping.containsKey(mappingKey)) {
                            Set<String> exceptions = contentTypesMapping.get(mappingKey);
                            if (!exceptions.contains(type)) {
                                contentDispositionAdded = setContentDisposition(resource);
                            }
                        } else {
                            contentDispositionAdded = setContentDisposition(resource);
                        }
                    }
                    if (!contentDispositionAdded) {
                        for (String path : contentDispositionPathsPfx) {
                            if (resourcePath.startsWith(path)) {
                                if (contentTypesMapping.containsKey(path)) {
                                    Set<String> exceptions = contentTypesMapping.get(path);
                                    if (!exceptions.contains(type)) {
                                        setContentDisposition(resource);
                                        break;
                                    }
                                } else {
                                    setContentDisposition(resource);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        private boolean setContentDisposition(Resource resource) {
            boolean contentDispositionAdded = false;
            if (!this.containsHeader(CONTENT_DISPOSTION) && this.isJcrData(resource)) {
                this.addHeader(CONTENT_DISPOSTION, CONTENT_DISPOSTION_ATTACHMENT);
                contentDispositionAdded = true;
            }
            return contentDispositionAdded;
        }

        private boolean isJcrData(Resource resource) {
            boolean jcrData = false;
            if (resource != null) {
                ValueMap props = resource.adaptTo(ValueMap.class);
                if (props != null && props.containsKey(PROP_JCR_DATA)) {
                    jcrData = true;
                } else {
                    Resource jcrContent = resource.getChild(JCR_CONTENT_LEAF);
                    if (jcrContent != null) {
                        ValueMap contentProps = jcrContent.adaptTo(ValueMap.class);
                        if (contentProps != null && contentProps.containsKey(PROP_JCR_DATA)) {
                            jcrData = true;
                        }
                    }
                    if (!jcrData && props == null) {
                        // A resource that does not adapt to a ValueMap is not
                        // a node but the shape of a property resource (e.g.
                        // .../file/jcr:content/jcr:data), whose response body
                        // is the property value itself. If it streams data,
                        // treat it as jcr:data so the header decision fails
                        // closed instead of silently skipping the header.
                        try (InputStream is = resource.adaptTo(InputStream.class)) {
                            jcrData = is != null;
                        } catch (IOException e) {
                            logger.debug("Failed to close InputStream adapted from resource {}", resource, e);
                        }
                    }
                }
            }
            return jcrData;
        }
    }
}
