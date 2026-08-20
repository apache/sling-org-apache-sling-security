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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import junitx.util.PrivateAccessor;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ValueMap;
import org.apache.sling.security.impl.ContentDispositionFilter.RewriterResponse;
import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.junit.Assert;
import org.junit.Test;

public class ContentDispositionFilterTest {

    private ContentDispositionFilter contentDispositionFilter;
    private final Mockery context = new JUnit4Mockery();

    private static final String PROP_JCR_DATA = "jcr:data";

    private static final String JCR_CONTENT_LEAF = "jcr:content";

    /**
     * Implementation of the annotation class used for the configuration of the ContentDispositionFilter.
     * Unfortunately there is no way to hide the compiler warning: http://stackoverflow.com/a/13261789/5155923
     */
    private static final class Configuration implements ContentDispositionFilterConfiguration {

        public Configuration(String[] paths, String[] excludedPaths, boolean enableForAllPaths) {
            super();
            this.paths = paths;
            this.excludedPaths = excludedPaths;
            this.enableForAllPaths = enableForAllPaths;
        }

        private final String paths[];
        private final String excludedPaths[];
        private final boolean enableForAllPaths;

        @Override
        public Class<? extends Annotation> annotationType() {
            return ContentDispositionFilterConfiguration.class;
        }

        @Override
        public String[] sling_content_disposition_paths() {
            return paths;
        }

        @Override
        public String[] sling_content_disposition_excluded_paths() {
            return excludedPaths;
        }

        @Override
        public boolean sling_content_disposition_all_paths() {
            return enableForAllPaths;
        }
    }

    private void callActivateWithConfiguration(String[] paths, String[] excludedPaths) throws Throwable {
        callActivateWithConfiguration(paths, excludedPaths, false);
    }

    private void callActivateWithConfiguration(String[] paths, String[] excludedPaths, boolean enableForAllPaths)
            throws Throwable {
        ContentDispositionFilterConfiguration configuration =
                new Configuration(paths, excludedPaths, enableForAllPaths);
        contentDispositionFilter = new ContentDispositionFilter(configuration);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void test_activator1() throws Throwable {
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {""});
        Set<String> contentDispositionPaths =
                (Set<String>) PrivateAccessor.getField(contentDispositionFilter, "contentDispositionPaths");
        Assert.assertEquals(1, contentDispositionPaths.size());
        String[] contentDispositionPathsPfx =
                (String[]) PrivateAccessor.getField(contentDispositionFilter, "contentDispositionPathsPfx");
        Assert.assertEquals(0, contentDispositionPathsPfx.length);
        Map<String, Set<String>> contentTypesMapping =
                (Map<String, Set<String>>) PrivateAccessor.getField(contentDispositionFilter, "contentTypesMapping");
        Assert.assertEquals(0, contentTypesMapping.size());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void test_activator2() throws Throwable {
        callActivateWithConfiguration(new String[] {"/content/usergenerated/*"}, new String[] {""});
        Set<String> contentDispositionPaths =
                (Set<String>) PrivateAccessor.getField(contentDispositionFilter, "contentDispositionPaths");
        Assert.assertEquals(0, contentDispositionPaths.size());
        String[] contentDispositionPathsPfx =
                (String[]) PrivateAccessor.getField(contentDispositionFilter, "contentDispositionPathsPfx");
        Assert.assertEquals(1, contentDispositionPathsPfx.length);
        Map<String, Set<String>> contentTypesMapping =
                (Map<String, Set<String>>) PrivateAccessor.getField(contentDispositionFilter, "contentTypesMapping");
        Assert.assertEquals(0, contentTypesMapping.size());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void test_activator3() throws Throwable {
        callActivateWithConfiguration(new String[] {"/libs", "/content/usergenerated/*"}, new String[] {""});
        Set<String> contentDispositionPaths =
                (Set<String>) PrivateAccessor.getField(contentDispositionFilter, "contentDispositionPaths");
        Assert.assertEquals(1, contentDispositionPaths.size());
        String[] contentDispositionPathsPfx =
                (String[]) PrivateAccessor.getField(contentDispositionFilter, "contentDispositionPathsPfx");
        Assert.assertEquals(1, contentDispositionPathsPfx.length);
        Map<String, Set<String>> contentTypesMapping =
                (Map<String, Set<String>>) PrivateAccessor.getField(contentDispositionFilter, "contentTypesMapping");
        Assert.assertEquals(0, contentTypesMapping.size());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void test_activator5() throws Throwable {
        callActivateWithConfiguration(new String[] {"*"}, new String[] {""});
        Set<String> contentDispositionPaths =
                (Set<String>) PrivateAccessor.getField(contentDispositionFilter, "contentDispositionPaths");
        Assert.assertEquals(0, contentDispositionPaths.size());
        String[] contentDispositionPathsPfx =
                (String[]) PrivateAccessor.getField(contentDispositionFilter, "contentDispositionPathsPfx");
        Assert.assertEquals(0, contentDispositionPathsPfx.length);
        Map<String, Set<String>> contentTypesMapping =
                (Map<String, Set<String>>) PrivateAccessor.getField(contentDispositionFilter, "contentTypesMapping");
        Assert.assertEquals(0, contentTypesMapping.size());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void test_activator6() throws Throwable {
        callActivateWithConfiguration(new String[] {"/libs:*"}, new String[] {""});
        Set<String> contentDispositionPaths =
                (Set<String>) PrivateAccessor.getField(contentDispositionFilter, "contentDispositionPaths");
        Assert.assertEquals(0, contentDispositionPaths.size());
        String[] contentDispositionPathsPfx =
                (String[]) PrivateAccessor.getField(contentDispositionFilter, "contentDispositionPathsPfx");
        Assert.assertEquals(0, contentDispositionPathsPfx.length);
        Map<String, Set<String>> contentTypesMapping =
                (Map<String, Set<String>>) PrivateAccessor.getField(contentDispositionFilter, "contentTypesMapping");
        Assert.assertEquals(0, contentTypesMapping.size());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void test_activator7() throws Throwable {
        callActivateWithConfiguration(
                new String[] {"/libs:text/html,text/plain", "/content/usergenerated/*:image/jpeg"}, new String[] {""});
        Set<String> contentDispositionPaths =
                (Set<String>) PrivateAccessor.getField(contentDispositionFilter, "contentDispositionPaths");
        Assert.assertEquals(1, contentDispositionPaths.size());
        String[] contentDispositionPathsPfx =
                (String[]) PrivateAccessor.getField(contentDispositionFilter, "contentDispositionPathsPfx");
        Assert.assertEquals(1, contentDispositionPathsPfx.length);
        Map<String, Set<String>> contentTypesMapping =
                (Map<String, Set<String>>) PrivateAccessor.getField(contentDispositionFilter, "contentTypesMapping");
        Assert.assertEquals(2, contentTypesMapping.size());
        Set<String> libsMapping = contentTypesMapping.get("/libs");
        Assert.assertEquals(2, libsMapping.size());
        libsMapping.contains("text/html");
        libsMapping.contains("text/plain");

        Set<String> userGeneratedMapping = contentTypesMapping.get("/content/usergenerated/");
        Assert.assertEquals(1, userGeneratedMapping.size());
        userGeneratedMapping.contains("image/jpeg");
    }

    @SuppressWarnings("unchecked")
    @Test
    public void test_activator8() throws Throwable {
        callActivateWithConfiguration(
                new String[] {"/libs:text/html,text/plain", "/content/usergenerated/*:image/jpeg"}, new String[] {});

        Set<String> contentDispositionExcludedPaths =
                (Set<String>) PrivateAccessor.getField(contentDispositionFilter, "contentDispositionExcludedPaths");
        Assert.assertEquals(0, contentDispositionExcludedPaths.size());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void test_activator9() throws Throwable {
        callActivateWithConfiguration(
                new String[] {"/libs:text/html,text/plain", "/content/usergenerated/*:image/jpeg"},
                new String[] {"/content", "/libs"});

        Set<String> contentDispositionExcludedPaths =
                (Set<String>) PrivateAccessor.getField(contentDispositionFilter, "contentDispositionExcludedPaths");
        Assert.assertEquals(2, contentDispositionExcludedPaths.size());
    }

    /**
     * A ':' in a JCR namespaced path segment (e.g. 'jcr:content') must not silently
     * truncate the configured path (which would leave the intended path unprotected).
     */
    @SuppressWarnings("unchecked")
    @Test
    public void test_activator_namespaced_path() throws Throwable {
        callActivateWithConfiguration(new String[] {"/content/site/file.svg/jcr:content"}, new String[] {""});
        Set<String> contentDispositionPaths =
                (Set<String>) PrivateAccessor.getField(contentDispositionFilter, "contentDispositionPaths");
        Assert.assertEquals(1, contentDispositionPaths.size());
        Assert.assertTrue(contentDispositionPaths.contains("/content/site/file.svg/jcr:content"));
        String[] contentDispositionPathsPfx =
                (String[]) PrivateAccessor.getField(contentDispositionFilter, "contentDispositionPathsPfx");
        Assert.assertEquals(0, contentDispositionPathsPfx.length);
        Map<String, Set<String>> contentTypesMapping =
                (Map<String, Set<String>>) PrivateAccessor.getField(contentDispositionFilter, "contentTypesMapping");
        Assert.assertEquals(0, contentTypesMapping.size());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void test_activator_namespaced_path_with_content_types() throws Throwable {
        callActivateWithConfiguration(
                new String[] {"/content/site/file.svg/jcr:content:image/svg+xml,text/html"}, new String[] {""});
        Set<String> contentDispositionPaths =
                (Set<String>) PrivateAccessor.getField(contentDispositionFilter, "contentDispositionPaths");
        Assert.assertEquals(1, contentDispositionPaths.size());
        Assert.assertTrue(contentDispositionPaths.contains("/content/site/file.svg/jcr:content"));
        Map<String, Set<String>> contentTypesMapping =
                (Map<String, Set<String>>) PrivateAccessor.getField(contentDispositionFilter, "contentTypesMapping");
        Assert.assertEquals(1, contentTypesMapping.size());
        Set<String> mapping = contentTypesMapping.get("/content/site/file.svg/jcr:content");
        Assert.assertEquals(2, mapping.size());
        Assert.assertTrue(mapping.contains("image/svg+xml"));
        Assert.assertTrue(mapping.contains("text/html"));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void test_activator_invalid_content_type_list_rejected() throws Throwable {
        callActivateWithConfiguration(new String[] {"/libs:text/html/*"}, new String[] {""});
        Set<String> contentDispositionPaths =
                (Set<String>) PrivateAccessor.getField(contentDispositionFilter, "contentDispositionPaths");
        Assert.assertEquals(0, contentDispositionPaths.size());
        String[] contentDispositionPathsPfx =
                (String[]) PrivateAccessor.getField(contentDispositionFilter, "contentDispositionPathsPfx");
        Assert.assertEquals(0, contentDispositionPathsPfx.length);
        Map<String, Set<String>> contentTypesMapping =
                (Map<String, Set<String>>) PrivateAccessor.getField(contentDispositionFilter, "contentTypesMapping");
        Assert.assertEquals(0, contentTypesMapping.size());
    }

    @SuppressWarnings("unchecked")
    @Test
    public void test_getContentTypes() throws Throwable {
        // null content types
        String contentType = null;
        Set<String> contentTypesSet = (Set<String>) PrivateAccessor.invoke(
                ContentDispositionFilter.class, "getContentTypes", new Class[] {String.class}, new Object[] {contentType
                });
        Assert.assertEquals(0, contentTypesSet.size());
        // empty content types
        contentType = "";
        contentTypesSet = (Set<String>) PrivateAccessor.invoke(
                ContentDispositionFilter.class, "getContentTypes", new Class[] {String.class}, new Object[] {contentType
                });
        Assert.assertEquals(0, contentTypesSet.size());
        contentType = "text/html";
        contentTypesSet = (Set<String>) PrivateAccessor.invoke(
                ContentDispositionFilter.class, "getContentTypes", new Class[] {String.class}, new Object[] {contentType
                });
        Assert.assertEquals(1, contentTypesSet.size());
        contentType = "text/html,text/plain";
        contentTypesSet = (Set<String>) PrivateAccessor.invoke(
                ContentDispositionFilter.class, "getContentTypes", new Class[] {String.class}, new Object[] {contentType
                });
        Assert.assertEquals(2, contentTypesSet.size());
    }

    @Test
    public void test_doFilter1() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {""});

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/libs"));
                allowing(response).setContentType("text/html");
                // CONTENT DISPOSITION MUST NOT SET
                never(response).addHeader("Content-Disposition", "attachment");
            }
        });
        ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response);

        rewriterResponse.setContentType("text/html");
    }

    @Test
    public void test_doFilter2() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {""});

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated/author"));
                allowing(response).setContentType("text/html");
                // CONTENT DISPOSITION MUST NOT SET
                never(response).addHeader("Content-Disposition", "attachment");
            }
        });
        ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response);

        rewriterResponse.setContentType("text/html");
    }

    @Test
    public void test_doFilter3() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {""});

        final AtomicInteger counter = new AtomicInteger();

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(response).containsHeader("Content-Disposition");
                will(returnValue(false));
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated"));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));
                allowing(response).setContentType("text/html");
                // CONTENT DISPOSITION IS SET
                exactly(1).of(response).addHeader("Content-Disposition", "attachment");
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response) {
                    @Override
                    public void addHeader(String name, String value) {
                        counter.incrementAndGet();
                    }
                };
        rewriterResponse.setContentType("text/html");
        Assert.assertEquals(1, counter.intValue());
    }

    @Test
    public void test_doFilter4() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        callActivateWithConfiguration(new String[] {"/content/usergenerated/*"}, new String[] {""});

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/libs"));
                allowing(response).setContentType("text/html");
                // CONTENT DISPOSITION MUST NOT SET
                never(response).addHeader("Content-Disposition", "attachment");
            }
        });
        ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response);
        rewriterResponse.setContentType("text/html");
    }

    @Test
    public void test_doFilter5() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);
        callActivateWithConfiguration(new String[] {"/content/usergenerated/*"}, new String[] {""});

        final AtomicInteger counter = new AtomicInteger();

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(response).containsHeader("Content-Disposition");
                will(returnValue(false));
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated/author"));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));
                allowing(response).setContentType("text/html");
                // CONTENT DISPOSITION IS SET
                exactly(1).of(response).addHeader("Content-Disposition", "attachment");
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response) {
                    @Override
                    public void addHeader(String name, String value) {
                        counter.incrementAndGet();
                    }
                };
        rewriterResponse.setContentType("text/html");
        Assert.assertEquals(1, counter.intValue());
    }

    @Test
    public void test_doFilter6() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);
        callActivateWithConfiguration(new String[] {"/content/usergenerated/*"}, new String[] {""});

        final AtomicInteger counter = new AtomicInteger();

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(response).containsHeader("Content-Disposition");
                will(returnValue(false));
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated/"));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));
                allowing(response).setContentType("text/html");
                // CONTENT DISPOSITION IS SET
                exactly(1).of(response).addHeader("Content-Disposition", "attachment");
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response) {
                    @Override
                    public void addHeader(String name, String value) {
                        counter.incrementAndGet();
                    }
                };
        rewriterResponse.setContentType("text/html");
        Assert.assertEquals(1, counter.intValue());
    }

    @Test
    public void test_doFilter7() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        callActivateWithConfiguration(new String[] {"/content/usergenerated:text/html,text/plain"}, new String[] {""});

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/libs"));
                allowing(response).setContentType("text/html");
                // CONTENT DISPOSITION MUST NOT SET
                never(response).addHeader("Content-Disposition", "attachment");
            }
        });
        ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response);

        rewriterResponse.setContentType("text/html");
    }

    @Test
    public void test_doFilter8() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        callActivateWithConfiguration(new String[] {"/content/usergenerated:text/html,text/plain"}, new String[] {""});

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated/author"));
                allowing(response).setContentType("text/html");
                // CONTENT DISPOSITION MUST NOT SET
                never(response).addHeader("Content-Disposition", "attachment");
            }
        });
        ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response);

        rewriterResponse.setContentType("text/html");
    }

    @Test
    public void test_doFilter9() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        callActivateWithConfiguration(new String[] {"/content/usergenerated:text/html,text/plain"}, new String[] {""});

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated"));
                allowing(response).setContentType("text/html");
                // CONTENT DISPOSITION MUST NOT SET
                never(response).addHeader("Content-Disposition", "attachment");
            }
        });
        ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response);

        rewriterResponse.setContentType("text/html");
    }

    @Test
    public void test_doFilter10() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);

        callActivateWithConfiguration(new String[] {"/content/usergenerated:text/html,text/plain"}, new String[] {""});

        final AtomicInteger counter = new AtomicInteger();

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(response).containsHeader("Content-Disposition");
                will(returnValue(false));
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "image/jpeg");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated"));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));
                allowing(response).setContentType("image/jpeg");
                // CONTENT DISPOSITION IS SET
                exactly(1).of(response).addHeader("Content-Disposition", "attachment");
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response) {
                    @Override
                    public void addHeader(String name, String value) {
                        counter.incrementAndGet();
                    }
                };
        rewriterResponse.setContentType("image/jpeg");
        Assert.assertEquals(1, counter.intValue());
    }

    @Test
    public void test_doFilter11() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        callActivateWithConfiguration(
                new String[] {"/content/usergenerated/*:text/html,text/plain"}, new String[] {""});

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/libs"));
                allowing(response).setContentType("text/html");
                // CONTENT DISPOSITION MUST NOT SET
                never(response).addHeader("Content-Disposition", "attachment");
            }
        });
        ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response);

        rewriterResponse.setContentType("text/html");
    }

    @Test
    public void test_doFilter12() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        callActivateWithConfiguration(
                new String[] {"/content/usergenerated/*:text/html,text/plain"}, new String[] {""});

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated/author"));
                allowing(response).setContentType("text/html");
                // CONTENT DISPOSITION MUST NOT SET
                never(response).addHeader("Content-Disposition", "attachment");
            }
        });
        ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response);

        rewriterResponse.setContentType("text/html");
    }

    @Test
    public void test_doFilter13() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        callActivateWithConfiguration(
                new String[] {"/content/usergenerated/*:text/html,text/plain"}, new String[] {""});

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated/author"));
                allowing(response).setContentType("text/html");
                // CONTENT DISPOSITION MUST NOT SET
                never(response).addHeader("Content-Disposition", "attachment");
            }
        });
        ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response);

        rewriterResponse.setContentType("text/html");
    }

    @Test
    public void test_doFilter14() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);
        callActivateWithConfiguration(
                new String[] {"/content/usergenerated/*:text/html,text/plain"}, new String[] {""});

        final AtomicInteger counter = new AtomicInteger();

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(response).containsHeader("Content-Disposition");
                will(returnValue(false));
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "image/jpeg");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated/author"));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));
                allowing(response).setContentType("image/jpeg");
                // CONTENT DISPOSITION IS SET
                exactly(1).of(response).addHeader("Content-Disposition", "attachment");
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response) {
                    @Override
                    public void addHeader(String name, String value) {
                        counter.incrementAndGet();
                    }
                };
        rewriterResponse.setContentType("image/jpeg");
        Assert.assertEquals(1, counter.intValue());
    }

    /**
     * A forward dispatch creates a new RewriterResponse for the forwarded-to
     * resource. A content type cached in the request attribute by the wrapper
     * of the outer dispatch (for a different, unprotected resource) must not
     * suppress the Content-Disposition evaluation for the protected resource
     * of this wrapper.
     * @throws Throwable
     */
    @Test
    public void test_doFilterForwardReevaluatesForNewResource() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {""});

        final AtomicInteger counter = new AtomicInteger();

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(response).containsHeader("Content-Disposition");
                will(returnValue(false));
                // the outer dispatch already cached the same content type for
                // a different (unprotected) resource
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue("text/html"));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated"));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));
                allowing(response).setContentType("text/html");
                // CONTENT DISPOSITION IS SET despite the cached content type
                exactly(1).of(response).addHeader("Content-Disposition", "attachment");
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response) {
                    @Override
                    public void addHeader(String name, String value) {
                        counter.incrementAndGet();
                    }
                };
        rewriterResponse.setContentType("text/html");
        Assert.assertEquals(1, counter.intValue());
    }

    /**
     * An exact (non-wildcard) protected path must also cover the file's
     * jcr:content child node, which serves the same binary (jcr:data) under a
     * second address.
     * @throws Throwable
     */
    @Test
    public void test_doFilterExactPathCoversJcrContentChild() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);
        callActivateWithConfiguration(new String[] {"/content/usergenerated/file.svg"}, new String[] {""});

        final AtomicInteger counter = new AtomicInteger();

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(response).containsHeader("Content-Disposition");
                will(returnValue(false));
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "image/svg+xml");
                allowing(request).getResource();
                will(returnValue(resource));
                // the jcr:content child of the protected file serves the same bytes
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated/file.svg/jcr:content"));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));
                allowing(response).setContentType("image/svg+xml");
                // CONTENT DISPOSITION IS SET
                exactly(1).of(response).addHeader("Content-Disposition", "attachment");
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response) {
                    @Override
                    public void addHeader(String name, String value) {
                        counter.incrementAndGet();
                    }
                };
        rewriterResponse.setContentType("image/svg+xml");
        Assert.assertEquals(1, counter.intValue());
    }

    /**
     * The content-type exceptions configured for an exact protected path apply
     * to the file's jcr:content child address as well.
     * @throws Throwable
     */
    @Test
    public void test_doFilterExactPathContentTypeMappingCoversJcrContentChild() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        callActivateWithConfiguration(new String[] {"/content/usergenerated/file.svg:image/jpeg"}, new String[] {""});

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "image/jpeg");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated/file.svg/jcr:content"));
                allowing(response).setContentType("image/jpeg");
                // CONTENT DISPOSITION MUST NOT SET (excepted content type)
                never(response).addHeader("Content-Disposition", "attachment");
            }
        });
        ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response);
        rewriterResponse.setContentType("image/jpeg");
    }

    /**
     * Test repeated setContentType calls don't add multiple headers, case 1 resetting the same mimetype
     * @throws Throwable
     */
    @Test
    public void test_doFilter15() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {""});

        final AtomicInteger counter = new AtomicInteger();

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(response).containsHeader("Content-Disposition");
                will(returnValue(false));
                exactly(1).of(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                exactly(1).of(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue("text/html"));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated"));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));
                allowing(response).setContentType("text/html");
                // CONTENT DISPOSITION IS SET
                exactly(1).of(response).addHeader("Content-Disposition", "attachment");
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response) {
                    @Override
                    public void addHeader(String name, String value) {
                        counter.incrementAndGet();
                    }
                };
        rewriterResponse.setContentType("text/html");
        rewriterResponse.setContentType("text/html");
        Assert.assertEquals(1, counter.intValue());
    }

    /**
     * Test repeated setContentType calls don't add multiple headers, case 2 changing mime type
     * @throws Throwable
     */
    @Test
    public void test_doFilter16() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {""});

        final AtomicInteger counter = new AtomicInteger();

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                exactly(1).of(response).containsHeader("Content-Disposition");
                will(returnValue(false));
                exactly(1).of(response).containsHeader("Content-Disposition");
                will(returnValue(true));
                exactly(1).of(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                exactly(1).of(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue("text/html"));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/xml");
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated"));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));
                allowing(response).setContentType("text/html");
                allowing(response).setContentType("text/xml");
                // CONTENT DISPOSITION IS SET
                exactly(1).of(response).addHeader("Content-Disposition", "attachment");
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response) {
                    @Override
                    public void addHeader(String name, String value) {
                        counter.incrementAndGet();
                    }
                };
        rewriterResponse.setContentType("text/html");
        rewriterResponse.setContentType("text/xml");
        Assert.assertEquals(1, counter.intValue());
    }

    @Test
    public void test_doFilter17() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);

        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {""}, false);

        final AtomicInteger counter = new AtomicInteger();

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                exactly(1).of(response).containsHeader("Content-Disposition");
                will(returnValue(false));
                exactly(1).of(response).containsHeader("Content-Disposition");
                will(returnValue(true));
                exactly(1).of(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                exactly(1).of(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue("text/html"));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/xml");
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/other"));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));
                allowing(response).setContentType("text/html");
                allowing(response).setContentType("text/xml");
                // CONTENT DISPOSITION IS NOT SET
                never(response).addHeader("Content-Disposition", "attachment");
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response) {
                    @Override
                    public void addHeader(String name, String value) {
                        counter.incrementAndGet();
                    }
                };
        rewriterResponse.setContentType("text/html");
        Assert.assertEquals(0, counter.intValue());
    }

    @Test
    public void test_doFilter18() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {""}, true);

        final AtomicInteger counter = new AtomicInteger();

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                exactly(1).of(response).containsHeader("Content-Disposition");
                will(returnValue(false));
                exactly(1).of(response).containsHeader("Content-Disposition");
                will(returnValue(true));
                exactly(1).of(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                exactly(1).of(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue("text/html"));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/xml");
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/other"));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));
                allowing(response).setContentType("text/html");
                allowing(response).setContentType("text/xml");
                // CONTENT DISPOSITION IS SET
                exactly(1).of(response).addHeader("Content-Disposition", "attachment");
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response) {
                    @Override
                    public void addHeader(String name, String value) {
                        counter.incrementAndGet();
                    }
                };
        rewriterResponse.setContentType("text/html");
        Assert.assertEquals(1, counter.intValue());
    }

    @Test
    public void test_doFilter19() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {"/content"}, true);

        final AtomicInteger counter = new AtomicInteger();

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                exactly(1).of(response).containsHeader("Content-Disposition");
                will(returnValue(false));
                exactly(1).of(response).containsHeader("Content-Disposition");
                will(returnValue(true));
                exactly(1).of(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                exactly(1).of(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue("text/html"));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/xml");
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/other"));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));
                allowing(response).setContentType("text/html");
                allowing(response).setContentType("text/xml");
                // CONTENT DISPOSITION IS SET
                exactly(1).of(response).addHeader("Content-Disposition", "attachment");
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response) {
                    @Override
                    public void addHeader(String name, String value) {
                        counter.incrementAndGet();
                    }
                };
        rewriterResponse.setContentType("text/html");
        Assert.assertEquals(1, counter.intValue());
    }

    @Test
    public void test_doFilter20() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {"/content/other"}, true);

        final AtomicInteger counter = new AtomicInteger();

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                exactly(1).of(response).containsHeader("Content-Disposition");
                will(returnValue(false));
                exactly(1).of(response).containsHeader("Content-Disposition");
                will(returnValue(true));
                exactly(1).of(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                exactly(1).of(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue("text/html"));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/xml");
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/other"));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));
                allowing(response).setContentType("text/html");
                allowing(response).setContentType("text/xml");
                // CONTENT DISPOSITION IS NOT SET
                never(response).addHeader("Content-Disposition", "attachment");
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response) {
                    @Override
                    public void addHeader(String name, String value) {
                        counter.incrementAndGet();
                    }
                };
        rewriterResponse.setContentType("text/html");
        Assert.assertEquals(0, counter.intValue());
    }

    @Test
    public void test_doFilter21() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {"/content"});

        final AtomicInteger counter = new AtomicInteger();

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(response).containsHeader("Content-Disposition");
                will(returnValue(false));
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated"));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));
                allowing(response).setContentType("text/html");
                // CONTENT DISPOSITION IS SET
                exactly(1).of(response).addHeader("Content-Disposition", "attachment");
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response) {
                    @Override
                    public void addHeader(String name, String value) {
                        counter.incrementAndGet();
                    }
                };
        rewriterResponse.setContentType("text/html");
        Assert.assertEquals(1, counter.intValue());
    }

    /**
     * Test multiple calls of setContentType which each result in a content-disposition header being needed.
     * Only one header should be added.
     * @throws Throwable
     */
    @Test
    public void test_doFilter21b() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {"/content"});

        final AtomicInteger counter = new AtomicInteger();

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(response).containsHeader("Content-Disposition");
                will(returnValue(false));
                exactly(1).of(response).reset();
                exactly(1).of(request).removeAttribute(RewriterResponse.ATTRIBUTE_NAME);
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated"));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));

                // Exactly 2 setContentType should reach the mock response.
                exactly(1).of(response).setContentType("text/html");
                exactly(1).of(response).setContentType("text/html");
                // CONTENT DISPOSITION IS SET
                exactly(1).of(response).addHeader("Content-Disposition", "attachment");
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response) {
                    @Override
                    public void addHeader(String name, String value) {
                        counter.incrementAndGet();
                    }
                };
        rewriterResponse.setContentType("text/html");
        Assert.assertEquals(1, counter.intValue());
        rewriterResponse.reset();

        /* Reset on the response clears all the headers, so if we setContentType again the content type header *and* the
         * content disposition should both reappear. The counter counts each time the content disposition header is added.
         * The setContentType calls on the mock response are enforced in the Expectations checked above.
         */
        rewriterResponse.setContentType("text/html");

        Assert.assertEquals(2, counter.intValue());
    }

    @Test
    public void test_doFilter22() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {"/content/usergenerated"});

        final AtomicInteger counter = new AtomicInteger();
        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(response).containsHeader("Content-Disposition");
                will(returnValue(false));
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated"));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));
                allowing(response).setContentType("text/html");
                // CONTENT DISPOSITION IS NOT SET
                never(response).addHeader("Content-Disposition", "attachment");
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response) {
                    @Override
                    public void addHeader(String name, String value) {
                        counter.incrementAndGet();
                    }
                };

        rewriterResponse.setContentType("text/html");
        Assert.assertEquals(0, counter.intValue());
    }

    @Test
    public void test_doFilter22b() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {"/content/usergenerated"});

        final AtomicInteger counter = new AtomicInteger();
        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(response).containsHeader("Content-Disposition");
                will(returnValue(false));
                exactly(1).of(response).reset();
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                exactly(1).of(request).removeAttribute(RewriterResponse.ATTRIBUTE_NAME);
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated"));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));
                exactly(2).of(response).setContentType("text/html");
                // CONTENT DISPOSITION IS NOT SET
                never(response).addHeader("Content-Disposition", "attachment");
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response) {
                    @Override
                    public void addHeader(String name, String value) {
                        counter.incrementAndGet();
                    }
                };

        rewriterResponse.setContentType("text/html");
        rewriterResponse.reset();
        rewriterResponse.setContentType("text/html");
        Assert.assertEquals(0, counter.intValue());
    }

    @Test
    public void test_isJcrData1() throws Throwable {
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {"/content/usergenerated"});
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = null;

        context.checking(new Expectations() {
            {
                allowing(request).getResource();
                will(returnValue(resource));
            }
        });

        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response);

        Boolean result = (Boolean) PrivateAccessor.invoke(
                rewriterResponse, "isJcrData", new Class[] {Resource.class}, new Object[] {resource});

        Assert.assertFalse(result);
    }

    @Test
    public void test_isJcrData2() throws Throwable {
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {"/content/usergenerated"});
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class);

        context.checking(new Expectations() {
            {
                allowing(request).getResource();
                will(returnValue(resource));
            }
        });

        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response);
        final ValueMap properties = context.mock(ValueMap.class);

        context.checking(new Expectations() {
            {
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));
            }
        });

        Boolean result = (Boolean) PrivateAccessor.invoke(
                rewriterResponse, "isJcrData", new Class[] {Resource.class}, new Object[] {resource});

        Assert.assertTrue(result);
    }

    @Test
    public void test_isJcrData3() throws Throwable {
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {"/content/usergenerated"});
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);

        final Resource resource = context.mock(Resource.class);
        final ValueMap properties = context.mock(ValueMap.class);

        context.checking(new Expectations() {
            {
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(false));
                allowing(resource).getChild(JCR_CONTENT_LEAF);
                will(returnValue(null));
            }
        });

        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response);

        Boolean result = (Boolean) PrivateAccessor.invoke(
                rewriterResponse, "isJcrData", new Class[] {Resource.class}, new Object[] {resource});

        Assert.assertFalse(result);
    }

    @Test
    public void test_isJcrData4() throws Throwable {
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {"/content/usergenerated"});
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);

        final Resource child = context.mock(Resource.class, "child");
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);
        final ValueMap childPropoerties = context.mock(ValueMap.class, "childPropoerties");

        context.checking(new Expectations() {
            {
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(false));
                allowing(resource).getChild(JCR_CONTENT_LEAF);
                will(returnValue(child));
                allowing(child).adaptTo(ValueMap.class);
                will(returnValue(childPropoerties));
                allowing(childPropoerties).containsKey(PROP_JCR_DATA);
                will(returnValue(false));
            }
        });

        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response);
        Boolean result = (Boolean) PrivateAccessor.invoke(
                rewriterResponse, "isJcrData", new Class[] {Resource.class}, new Object[] {resource});

        Assert.assertFalse(result);
    }

    @Test
    public void test_isJcrData5() throws Throwable {
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {"/content/usergenerated"});
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);

        final Resource child = context.mock(Resource.class, "child");
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);
        final ValueMap childPropoerties = context.mock(ValueMap.class, "childPropoerties");

        context.checking(new Expectations() {
            {
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(false));
                allowing(resource).getChild(JCR_CONTENT_LEAF);
                will(returnValue(child));
                allowing(child).adaptTo(ValueMap.class);
                will(returnValue(childPropoerties));
                allowing(childPropoerties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));
            }
        });

        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response);

        Boolean result = (Boolean) PrivateAccessor.invoke(
                rewriterResponse, "isJcrData", new Class[] {Resource.class}, new Object[] {resource});

        Assert.assertTrue(result);
    }

    @Test
    public void test_isJcrData6() throws Throwable {
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {"/content/usergenerated"});
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);

        final Resource resource = context.mock(Resource.class);

        context.checking(new Expectations() {
            {
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(null));
                allowing(resource).getChild(JCR_CONTENT_LEAF);
                will(returnValue(null));
                allowing(resource).adaptTo(InputStream.class);
                will(returnValue(null));
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response);

        Boolean result = (Boolean) PrivateAccessor.invoke(
                rewriterResponse, "isJcrData", new Class[] {Resource.class}, new Object[] {resource});

        Assert.assertFalse(result);
    }

    /**
     * A property resource (e.g. .../file/jcr:content/jcr:data) does not adapt
     * to a ValueMap and has no jcr:content child, but its response body is the
     * repository binary itself - it must be treated as jcr:data.
     */
    @Test
    public void test_isJcrData8() throws Throwable {
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {"/content/usergenerated"});
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);

        final Resource resource = context.mock(Resource.class);
        final InputStream stream = new ByteArrayInputStream(new byte[0]);

        context.checking(new Expectations() {
            {
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(null));
                allowing(resource).getChild(JCR_CONTENT_LEAF);
                will(returnValue(null));
                allowing(resource).adaptTo(InputStream.class);
                will(returnValue(stream));
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response);

        Boolean result = (Boolean) PrivateAccessor.invoke(
                rewriterResponse, "isJcrData", new Class[] {Resource.class}, new Object[] {resource});

        Assert.assertTrue(result);
    }

    @Test
    public void test_isJcrData7() throws Throwable {
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {"/content/usergenerated"});
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource child = context.mock(Resource.class, "child");
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);

        context.checking(new Expectations() {
            {
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(false));
                allowing(resource).getChild(JCR_CONTENT_LEAF);
                will(returnValue(child));
                allowing(child).adaptTo(ValueMap.class);
                will(returnValue(null));
            }
        });

        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response);

        Boolean result = (Boolean) PrivateAccessor.invoke(
                rewriterResponse, "isJcrData", new Class[] {Resource.class}, new Object[] {resource});

        Assert.assertFalse(result);
    }

    /**
     * Regression: setting the media type via setHeader("Content-Type", ...) is equivalent
     * to setContentType(...) and must be mediated the same way (it used to bypass the filter).
     */
    @Test
    public void test_setHeaderContentTypeIsMediated() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {""});

        final AtomicInteger counter = new AtomicInteger();

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(response).containsHeader("Content-Disposition");
                will(returnValue(false));
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "image/svg+xml");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated"));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));
                allowing(response).setContentType("image/svg+xml");
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response) {
                    @Override
                    public void addHeader(String name, String value) {
                        counter.incrementAndGet();
                    }
                };
        rewriterResponse.setHeader("Content-Type", "image/svg+xml");
        Assert.assertEquals(1, counter.intValue());
    }

    /**
     * Regression: the header name comparison must be case-insensitive.
     */
    @Test
    public void test_setHeaderContentTypeIsMediatedCaseInsensitive() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {""});

        final AtomicInteger counter = new AtomicInteger();

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(response).containsHeader("Content-Disposition");
                will(returnValue(false));
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated"));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));
                allowing(response).setContentType("text/html");
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response) {
                    @Override
                    public void addHeader(String name, String value) {
                        counter.incrementAndGet();
                    }
                };
        rewriterResponse.setHeader("content-type", "text/html");
        Assert.assertEquals(1, counter.intValue());
    }

    /**
     * Regression: addHeader("Content-Type", ...) must be mediated as well.
     */
    @Test
    public void test_addHeaderContentTypeIsMediated() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {""});

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(response).containsHeader("Content-Disposition");
                will(returnValue(false));
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).setAttribute(RewriterResponse.ATTRIBUTE_NAME, "text/html");
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated"));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));
                allowing(response).setContentType("text/html");
                // CONTENT DISPOSITION IS SET
                exactly(1).of(response).addHeader("Content-Disposition", "attachment");
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response);
        rewriterResponse.addHeader("Content-Type", "text/html");
        context.assertIsSatisfied();
    }

    /**
     * Regression: a response which never declares a content type (browsers would
     * content-sniff it) must still get the Content-Disposition header before the
     * body can be written.
     */
    @Test
    public void test_typelessResponseIsMediatedOnOutput() throws Throwable {
        final SlingHttpServletRequest request = context.mock(SlingHttpServletRequest.class);
        final SlingHttpServletResponse response = context.mock(SlingHttpServletResponse.class);
        final Resource resource = context.mock(Resource.class, "resource");
        final ValueMap properties = context.mock(ValueMap.class);
        callActivateWithConfiguration(new String[] {"/content/usergenerated"}, new String[] {""});

        context.checking(new Expectations() {
            {
                allowing(request).getMethod();
                will(returnValue("GET"));
                allowing(request).getAttribute(RewriterResponse.ATTRIBUTE_NAME);
                will(returnValue(null));
                allowing(request).getResource();
                will(returnValue(resource));
                allowing(resource).getPath();
                will(returnValue("/content/usergenerated"));
                allowing(resource).adaptTo(ValueMap.class);
                will(returnValue(properties));
                allowing(properties).containsKey(PROP_JCR_DATA);
                will(returnValue(true));
                allowing(response).getContentType();
                will(returnValue(null));
                allowing(response).containsHeader("Content-Disposition");
                will(returnValue(false));
                allowing(response).getOutputStream();
                will(returnValue(null));
                // CONTENT DISPOSITION IS SET
                exactly(1).of(response).addHeader("Content-Disposition", "attachment");
            }
        });
        final ContentDispositionFilter.RewriterResponse rewriterResponse =
                contentDispositionFilter.new RewriterResponse(request, response);
        rewriterResponse.getOutputStream();
        context.assertIsSatisfied();
    }
}
