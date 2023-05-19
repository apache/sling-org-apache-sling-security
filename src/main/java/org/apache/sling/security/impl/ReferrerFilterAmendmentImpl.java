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

import java.util.Optional;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

@Component(service = ReferrerFilterAmendment.class)
@Designate(factory = true, ocd = ReferrerFilterAmendmentImpl.Config.class)
public class ReferrerFilterAmendmentImpl implements ReferrerFilterAmendment {

    private final Config config;

    @Activate
    public ReferrerFilterAmendmentImpl(Config config) {
        this.config = config;
    }

    @Override
    public String[] allowHosts() {
        return Optional.ofNullable(config.allow_hosts()).orElse(new String[0]);
    }

    @Override
    public String[] allowHostsRegex() {
        return Optional.ofNullable(config.allow_hosts_regexp()).orElse(new String[0]);
    }

    @Override
    public String[] excludeAgentsRegex() {
        return Optional.ofNullable(config.exclude_agents_regexp()).orElse(new String[0]);
    }

    @Override
    public String[] excludePaths() {
        return Optional.ofNullable(config.exclude_paths()).orElse(new String[0]);
    }

    @ObjectClassDefinition(name = "Apache Sling Referrer Filter Amendment", description = "Amend the primary list of Referrer Filter allow hosts with additional hosts")
    public @interface Config {

        @AttributeDefinition(name = "Allow Hosts", description = "List of allowed hosts for the referrer which are added to the list of default hosts. "
                + "It is matched against the full referrer URL in the format \"<scheme>://<host>:<port>\". "
                + "If port is 0, it is not taken into consideration. The default list contains all host names "
                + "and IPs bound to all NICs found in the system plus \"localhost\", \"127.0.0.1\", \"[::1]\" for protocols \"http\" and \"https\". "
                + "If given value does not have a \":\" entries for both http and https are transparently generated.")
        String[] allow_hosts() default {};

        /**
         * Allow referrer regex hosts property
         */
        @AttributeDefinition(name = "Allow Regexp Host", description = "List of allowed regular expression for the referrer. "
                + "It is matched against the full referrer URL in the format \"<scheme>://<host>:<port>\". "
                + "Evaluated in addition to the default list and the given allowed hosts (see above)!")
        String[] allow_hosts_regexp() default {};

        /**
         * Excluded regexp user agents property
         */
        @AttributeDefinition(name = "Exclude Regexp User Agent", description = "List of regexp for user agents not to check the referrer")
        String[] exclude_agents_regexp() default {};

        /**
         * Excluded the configured paths from the referrer check
         */
        @AttributeDefinition(name = "Exclude Paths", description = "List of paths for which not to check the referrer")
        String[] exclude_paths() default {};

    }

}