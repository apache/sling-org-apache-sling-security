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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.annotation.Annotation;
import java.util.Collections;

import javax.servlet.http.HttpServletRequest;

import org.apache.sling.security.impl.ReferrerFilterAmendmentImpl.Config;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class ReferrerFilterTest {

    protected ReferrerFilter filter;

    @Before
    public void setup() {
        ReferrerFilter.Config config = createConfiguration(false, new String[] { "relhost" },
                new String[] { "http://([^.]*.)?abshost:80", "^app://.+" },
                new String[] { "[a-zA-Z]*\\/[0-9]*\\.[0-9]*;Some-Agent\\s.*" },
                new String[] { null, "/test_path" });
        filter = new ReferrerFilter(config, Collections.emptyList());
    }

    private static ReferrerFilter.Config createConfiguration(boolean allowEmpty, String[] allowHosts,
            String[] allowHostsRexexp,
            String[] excludeAgentsRegexp, String[] excludePaths) {
        return new ReferrerFilter.Config() {
            @Override
            public Class<? extends Annotation> annotationType() {
                return null;
            }

            @Override
            public boolean allow_empty() {
                return allowEmpty;
            }

            @Override
            public String[] allow_hosts() {
                return allowHosts;
            }

            @Override
            public String[] allow_hosts_regexp() {
                return allowHostsRexexp;
            }

            @Override
            public String[] filter_methods() {
                return new String[0];
            }

            @Override
            public String[] exclude_agents_regexp() {
                return excludeAgentsRegexp;
            }

            @Override
            public String[] exclude_paths() {
                return excludePaths;
            }
        };
    }

    @Test
    public void testHostName() {
        Assert.assertEquals("somehost", filter.getHost("http://somehost").host);
        Assert.assertEquals("somehost", filter.getHost("http://somehost/somewhere").host);
        Assert.assertEquals("somehost", filter.getHost("http://somehost:4242/somewhere").host);
        Assert.assertEquals("somehost", filter.getHost("http://admin@somehost/somewhere").host);
        Assert.assertEquals("somehost", filter.getHost("http://admin@somehost/somewhere?invald=@gagga").host);
        Assert.assertEquals("somehost", filter.getHost("http://admin@somehost:1/somewhere").host);
        Assert.assertEquals("somehost", filter.getHost("http://admin:admin@somehost/somewhere").host);
        Assert.assertEquals("somehost", filter.getHost("http://admin:admin@somehost:4343/somewhere").host);
        Assert.assertEquals("localhost", filter.getHost("http://localhost").host);
        Assert.assertEquals("127.0.0.1", filter.getHost("http://127.0.0.1").host);
        Assert.assertEquals("localhost", filter.getHost("http://localhost:535").host);
        Assert.assertEquals("127.0.0.1", filter.getHost("http://127.0.0.1:242").host);
        Assert.assertEquals("localhost", filter.getHost("http://localhost:256235/etewteq.ff").host);
        Assert.assertEquals("127.0.0.1", filter.getHost("http://127.0.0.1/wetew.qerq").host);
        Assert.assertNull(filter.getHost("http:/admin:admin@somehost:4343/somewhere"));
    }

    private static HttpServletRequest getRequest(final String referrer, final String userAgent, final String pathInfo) {
        final HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("POST");
        if (pathInfo != null) {
            when(request.getRequestURI()).thenReturn("http://somehost/somewhere" + pathInfo);
            when(request.getPathInfo()).thenReturn(pathInfo);
        } else {
            when(request.getRequestURI()).thenReturn("http://somehost/somewhere");
        }
        when(request.getHeader("referer")).thenReturn(referrer);
        if (userAgent != null && userAgent.length() > 0) {
            when(request.getHeader("User-Agent")).thenReturn(userAgent);
        }
        return request;
    }

    private static HttpServletRequest getRequest(final String referrer, final String userAgent) {
        return getRequest(referrer, userAgent, null);
    }

    private static HttpServletRequest getRequest(final String referrer) {
        return getRequest(referrer, null);
    }

    @Test
    public void testValidRequest() {
        assertFalse(filter.isValidRequest(getRequest(null)));
        assertTrue(filter.isValidRequest(getRequest("relative")));
        assertTrue(filter.isValidRequest(getRequest("/relative/too")));
        assertTrue(filter.isValidRequest(getRequest("/relative/but/[illegal]")));
        assertFalse(filter.isValidRequest(getRequest("http://somehost")));
        assertTrue(filter.isValidRequest(getRequest("http://localhost")));
        assertTrue(filter.isValidRequest(getRequest("http://127.0.0.1")));
        assertFalse(filter.isValidRequest(getRequest("http://somehost/but/[illegal]")));
        assertTrue(filter.isValidRequest(getRequest("http://relhost")));
        assertTrue(filter.isValidRequest(getRequest("http://relhost:9001")));
        assertFalse(filter.isValidRequest(getRequest("http://abshost:9001")));
        assertFalse(filter.isValidRequest(getRequest("https://abshost:80")));
        assertTrue(filter.isValidRequest(getRequest("http://abshost:80")));
        assertFalse(filter.isValidRequest(getRequest("http://abshost:9001")));
        assertTrue(filter.isValidRequest(getRequest("http://another.abshost:80")));
        assertFalse(filter.isValidRequest(getRequest("http://yet.another.abshost:80")));
        assertTrue(filter.isValidRequest(getRequest("app://yet.another.abshost:80")));
        assertFalse(filter.isValidRequest(getRequest("?://")));
    }

    @Test
    public void testExcludedPath() {
        assertTrue(filter.isValidRequest(getRequest(null, null, "/test_path")));
        assertFalse(filter.isValidRequest(getRequest(null, null, "/test_path/subtree")));
        assertFalse(filter.isValidRequest(getRequest(null, null, "/test_path_sibling")));

        assertTrue(filter.isValidRequest(getRequest("relative", null, "/test_path")));
        assertTrue(filter.isValidRequest(getRequest("http://yet.another.abshost:80", null, "/test_path")));
    }

    @Test
    public void testExcludedPathNull() {
        ReferrerFilter rf = new ReferrerFilter(createConfiguration(false, null, null, null, null),
                Collections.emptyList());

        assertFalse(rf.isValidRequest(getRequest(null, null, "/test_path")));
        assertFalse(rf.isValidRequest(getRequest(null, null, "/test_path/subtree")));
        assertFalse(rf.isValidRequest(getRequest(null, null, "/test_path_sibling")));

        assertTrue(rf.isValidRequest(getRequest("relative", null, "/test_path")));
        assertFalse(rf.isValidRequest(getRequest("http://yet.another.abshost:80", null, "/test_path")));
    }

    @Test
    public void testWithAmendments() {
        ReferrerFilterAmendment amendment = new ReferrerFilterAmendmentImpl(new Config() {

            @Override
            public Class<? extends Annotation> annotationType() {
                throw new UnsupportedOperationException("Unimplemented method 'annotationType'");
            }

            @Override
            public String[] allow_hosts() {
                return new String[]{"test.com"};
            }

            @Override
            public String[] allow_hosts_regexp() {
                return new String[]{".*test2.com.*"};
            }

            @Override
            public String[] exclude_agents_regexp() {
                return null;
            }

            @Override
            public String[] exclude_paths() {
                return new String[]{"/testpath2"};
            }
            
        });
        ReferrerFilter rf = new ReferrerFilter(createConfiguration(false, null, new String[]{".*test1.com.*"}, null, null), Collections.singletonList(amendment));
        
        assertTrue(rf.isValidRequest(getRequest(null, null, "/testpath2")));
        assertFalse(rf.isValidRequest(getRequest(null, null, "/test1path")));

        assertFalse(rf.isValidRequest(getRequest("http://testnotvalid.com:80", null, "/test_path")));
        assertTrue(rf.isValidRequest(getRequest("http://test1.com:80", null, "/test_path")));
        assertTrue(rf.isValidRequest(getRequest("http://test2.com:80", null, "/test_path")));
    }


    @Test
    public void testAllowsWithOrigin(){
        HttpServletRequest request = getRequest(null);
        when(request.getHeader("origin")).thenReturn("http://abshost");
        Assert.assertEquals(true, filter.isValidRequest(request));
    }

    @Test
    public void testAllowEmpty() {
        ReferrerFilter rf = new ReferrerFilter(createConfiguration(true, null, null, null, null),
                Collections.emptyList());

        assertTrue(rf.isValidRequest(getRequest(null, null, "/test_path")));
        assertTrue(rf.isValidRequest(getRequest("", null, null)));
    }

    @Test
    public void testIsBrowserRequest() {
        String userAgent = "Mozilla/5.0;Some-Agent (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/603.2.4 (KHTML, like Gecko)";
        assertFalse(filter.isBrowserRequest(getRequest(null, userAgent)));
        userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/603.2.4 (KHTML, like Gecko)";
        assertTrue(filter.isBrowserRequest(getRequest(null, userAgent)));
    }
}
