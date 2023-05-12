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

/**
 * Amends the primary configuration of Referrer Filter
 */
public interface ReferrerFilterAmendment {
    /**
     * @return List of allowed hosts for the referrer which are added to the list of
     *         default hosts.
     */
    String[] allowHosts();

    /**
     * @return List of allowed regular expression for the referrer.
     */
    String[] allowHostsRegex();

    /**
     * @return List of regexp for user agents not to check the referrer
     */
    String[] excludeAgentsRegex();

    /**
     * @return List of paths for which not to check the referrer
     */
    String[] excludePaths();
}
